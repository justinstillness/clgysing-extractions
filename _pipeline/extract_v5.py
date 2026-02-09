#!/usr/bin/env python3
"""
MCP Traffic Extraction Script (Component 2) — v5
==================================================
Parses socat -v raw traffic logs into:
  Stream 1: Structured JSONL (all tool calls)
  Stream 2: Clean extracted text files (notebook_query only)

v5 changes: Signal String (SERAPH) integration
  - Replaces META_PATTERN with SERAPH signal string parsing
  - Implements 3-tier routing (tagged+known, tagged+unknown, untagged)
  - Adds socat artifact stripping (D-024 fix)
  - Updated pass type codebook per v1.0 Signal String spec
  - Semantic filenames from SERAPH fields

v4 changes: Rewritten parsing for real socat -v format + fallback extraction
v2 changes: Rewritten parsing for real socat -v format

Usage:
  python3 extract.py                    # Process today's log
  python3 extract.py 2026-02-06         # Process specific date
  python3 extract.py --all              # Process all traffic logs
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# === CONFIGURATION ===
TRAFFIC_DIR = Path("/home/ubuntu/mcp-logs/traffic")
RAW_DIR = Path("/home/ubuntu/mcp-logs/raw")
EXTRACTED_DIR = Path("/home/ubuntu/mcp-logs/extracted")

# === SIGNAL STRING (SERAPH) PARSING ===

# Signal String pattern: [SERAPH: KEY=value, KEY=value, ...]
SERAPH_PATTERN = re.compile(
    r'\[SERAPH:\s*(.+?)\]'
)

# Legacy META pattern (for backward compatibility with pre-v5 extractions)
META_PATTERN = re.compile(
    r'\[META:(?P<sp>SP\d+)\|(?P<ptype>[A-Z]{2})\|(?P<seq>\d+)\|(?P<desc>[^\]]+)\]'
)

# Pass type codebook — from v1.0 Signal String Initial Conventions
# Validated extraction passes
PASS_TYPE_NAMES = {
    'TM': 'Theme Mapping',
    'TX': 'Thematic Extraction',
    'VX': 'Vocabulary Extraction',
    'TS': 'Thesis String Extraction',
    'EV': 'Evaluation Pass',
    'GD': 'Gap Detection',
    'GX': 'Gap Extraction',
    'CL': 'Classification',
    # Validated modalities
    'TL': 'Thesis-Lens Extraction',
    # Administrative / non-extraction passes
    'PE': 'Pre-Extraction Evaluation',
    'QC': 'Query Context',
    'NB': 'Notebook Administration',
    'GL': 'Glossary Generation',
    'CR': 'Cross-Reference Mapping',
    # Legacy codes (backward compat)
    'CE': 'Concept Extraction (deprecated - TX)',
    'FP': 'Full Pass (legacy)',
}

# Socat artifact pattern (D-024 fix)
# Matches stray chunk headers embedded in content body
# Example: < 2026/02/08 05:42:04.000478245 length=6644 from=8693 to=15336
SOCAT_ARTIFACT_RE = re.compile(
    r'^[<>]\s+\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+length=\d+\s+from=\d+\s+to=\d+\s*$',
    re.MULTILINE
)

# Block header pattern - matches both start-of-line AND mid-line occurrences
HEADER_RE = re.compile(
    r'([><])\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+length=(\d+)\s+from=(\d+)\s+to=(\d+)'
)


def parse_seraph_string(query_text):
    """Parse a SERAPH signal string from query text.
    
    Returns dict of parsed fields, or None if no signal string found.
    
    Signal String format:
      [SERAPH: PROJECT=clgysing, SP=03, PASS=VX, NUM=01, THEME=identity-mechanics, SESSION=013]
    """
    match = SERAPH_PATTERN.search(query_text)
    if not match:
        return None
    
    fields = {}
    raw_fields = match.group(1)
    
    for pair in raw_fields.split(','):
        pair = pair.strip()
        if '=' in pair:
            key, value = pair.split('=', 1)
            fields[key.strip().upper()] = value.strip()
    
    # Validate required fields
    required = ['PROJECT', 'PASS', 'NUM']
    for req in required:
        if req not in fields:
            return None  # Missing required field - treat as untagged
    
    return fields


def strip_seraph_string(query_text):
    """Remove the SERAPH signal string from query text for clean display."""
    return SERAPH_PATTERN.sub('', query_text).strip()


def strip_socat_artifacts(text):
    """Remove stray socat chunk headers from extracted content (D-024 fix)."""
    return SOCAT_ARTIFACT_RE.sub('', text)


def classify_pass_type(pass_code):
    """Classify a pass type code into routing tier.
    
    Returns:
        ('known', name) - Tier 1: recognized pass type
        ('unknown', code) - Tier 2: unrecognized pass type
    """
    if pass_code in PASS_TYPE_NAMES:
        return ('known', PASS_TYPE_NAMES[pass_code])
    return ('unknown', pass_code)


def parse_socat_log(log_path):
    """Parse a socat -v log file into a list of directional blocks."""
    raw_text = open(log_path, 'r', errors='replace').read()
    headers = list(HEADER_RE.finditer(raw_text))
    if not headers:
        return []
    
    blocks = []
    for i, m in enumerate(headers):
        direction = m.group(1)
        timestamp = m.group(2)
        length = int(m.group(3))
        
        data_start = m.end()
        nl = raw_text.find('\n', data_start)
        if nl == -1:
            data_start_line = data_start
        else:
            data_start_line = nl + 1
        
        if i + 1 < len(headers):
            next_header_start = headers[i + 1].start()
            data_end = next_header_start
        else:
            data_end = len(raw_text)
        
        pre_data = ''
        line_start = raw_text.rfind('\n', 0, m.start())
        if line_start == -1:
            line_start = 0
        else:
            line_start += 1
        
        if line_start < m.start():
            pre_data = raw_text[line_start:m.start()]
        
        data = raw_text[data_start_line:data_end]
        
        blocks.append({
            'direction': direction,
            'timestamp': timestamp,
            'length': length,
            'data': data,
            'pre_data': pre_data,
        })
    
    return blocks


def clean_socat_text(text):
    """Clean socat -v text: remove literal \\r sequences."""
    return text.replace('\\r', '')


def extract_json_from_text(text):
    """Extract the first complete JSON object from text using brace matching."""
    start = text.find('{')
    if start == -1:
        return None, -1
    
    depth = 0
    in_string = False
    escape_next = False
    
    for i in range(start, len(text)):
        c = text[i]
        
        if escape_next:
            escape_next = False
            continue
        
        if c == '\\':
            if in_string:
                escape_next = True
            continue
        
        if c == '"' and not escape_next:
            in_string = not in_string
            continue
        
        if in_string:
            continue
        
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i+1]), i+1
                except json.JSONDecodeError:
                    return None, -1
    
    return None, -1


def extract_all_json_from_text(text):
    """Extract ALL JSON objects from text."""
    results = []
    pos = 0
    while pos < len(text):
        obj, end_pos = extract_json_from_text(text[pos:])
        if obj is None:
            break
        results.append(obj)
        pos += end_pos
    return results


def extract_sse_data(text):
    """Extract JSON from SSE format in response blocks."""
    cleaned = clean_socat_text(text)
    
    results = []
    for line in cleaned.split('\n'):
        line = line.strip()
        
        data_idx = line.find('data: {')
        if data_idx > 0:
            prefix = line[:data_idx]
            if all(c in '0123456789abcdefABCDEF' for c in prefix):
                line = line[data_idx:]
        elif data_idx == -1:
            continue
        
        if line.startswith('data: '):
            payload = line[6:]
            if payload.startswith('{'):
                normalized = payload
                prev = None
                while prev != normalized:
                    prev = normalized
                    normalized = normalized.replace('\\\\', '\\')
                
                try:
                    results.append(json.loads(normalized))
                except json.JSONDecodeError:
                    obj, _ = extract_json_from_text(normalized)
                    if obj:
                        results.append(obj)
    
    if not results and '"structuredContent":{' in text:
        fallback = _extract_structured_content_fallback(text)
        if fallback:
            results.append(fallback)
    
    return results


def _extract_structured_content_fallback(text):
    """Fallback extraction when normal SSE JSON parsing fails."""
    rpc_id = None
    id_match = re.search(r'"id"\s*:\s*(\d+)', text)
    if id_match:
        rpc_id = int(id_match.group(1))
    
    answer_start_marker = '"answer":"'
    sc_pos = text.find('"structuredContent":{')
    if sc_pos < 0:
        return None
    
    answer_start = text.find(answer_start_marker, sc_pos)
    if answer_start < 0:
        return None
    answer_start += len(answer_start_marker)
    
    answer_end = -1
    for end_marker in ['","conversation_id":"', '","sources_used":']:
        pos = text.find(end_marker, answer_start)
        if pos > 0 and (answer_end < 0 or pos < answer_end):
            answer_end = pos
    
    if answer_end < 0:
        return None
    
    answer_raw = text[answer_start:answer_end]
    answer = answer_raw.replace('\\n', '\n').replace('\\r', '').replace('\\"', '"')
    
    conv_id = None
    conv_match = re.search(r'"conversation_id"\s*:\s*"([^"]+)"', text[sc_pos:])
    if conv_match:
        conv_id = conv_match.group(1)
    
    return {
        'id': rpc_id,
        'result': {
            'structuredContent': {
                'status': 'success',
                'answer': answer,
                'conversation_id': conv_id or '',
                'sources_used': [],
            }
        }
    }

def _raw_fallback_extract(raw_log, blocks, block_idx):
    """Extract answer from raw log when block-based SSE parsing fails."""
    block_ts = blocks[block_idx]['timestamp']
    block_raw_pos = raw_log.find(block_ts)
    if block_raw_pos < 0:
        return None
    
    end_raw_pos = len(raw_log)
    for j in range(block_idx + 1, min(block_idx + 20, len(blocks))):
        if blocks[j]['direction'] == '>':
            next_ts = blocks[j]['timestamp']
            next_pos = raw_log.find(next_ts, block_raw_pos + 1)
            if next_pos > 0:
                end_raw_pos = next_pos
                break
    
    region = raw_log[block_raw_pos:end_raw_pos]
    
    sc_pos = region.find('"structuredContent":{')
    if sc_pos < 0:
        return None
    
    ans_pos = region.find('"answer":"', sc_pos)
    if ans_pos < 0:
        return None
    ans_start = ans_pos + len('"answer":"')
    
    ans_end = -1
    for marker in ['","conversation_id":"', '","sources_used":']:
        pos = region.find(marker, ans_start)
        if pos > 0 and (ans_end < 0 or pos < ans_end):
            ans_end = pos
    
    if ans_end < 0:
        return None
    
    answer_raw = region[ans_start:ans_end]
    answer = answer_raw.replace('\\n', '\n').replace('\\r', '').replace('\\"', '"')
    
    conv_id = ''
    conv_match = re.search(r'"conversation_id"\s*:\s*"([^"]+)"', region[sc_pos:])
    if conv_match:
        conv_id = conv_match.group(1)
    
    rpc_id = None
    id_match = re.search(r'"id"\s*:\s*(\d+)', region[:sc_pos])
    if id_match:
        rpc_id = int(id_match.group(1))
    
    return {
        'id': rpc_id,
        'result': {
            'structuredContent': {
                'status': 'success',
                'answer': answer,
                'conversation_id': conv_id,
                'sources_used': [],
            }
        }
    }


def assemble_response_data(blocks, start_idx):
    """Assemble complete SSE response data from potentially split blocks."""
    block = blocks[start_idx]
    assembled = block['data']
    
    for j in range(start_idx + 1, min(start_idx + 10, len(blocks))):
        next_block = blocks[j]
        
        if next_block['pre_data']:
            assembled += next_block['pre_data']
        
        if next_block['direction'] == '>':
            break
        
        if next_block['data'].strip() and 'event: message' in next_block['data']:
            break
        
        if next_block['data'].strip() in ('', '0', '\\r', '\\r\\n\\r\\n'):
            continue
        
        if len(next_block['data'].strip()) > 20:
            break
    
    return assembled


def correlate_tool_calls(blocks, debug=False, raw_log=None):
    """Correlate request/response blocks into tool call records."""
    tool_calls = []
    pending_requests = []
    
    for i, block in enumerate(blocks):
        texts_to_check = []
        
        if block['direction'] == '>':
            texts_to_check.append(('data', block['data']))
        
        for source, text in texts_to_check:
            cleaned = clean_socat_text(text)
            jsons = extract_all_json_from_text(cleaned)
            
            for body_json in jsons:
                method = body_json.get('method', '')
                rpc_id = body_json.get('id')
                
                if method == 'tools/call' and rpc_id is not None:
                    params = body_json.get('params', {})
                    tool_name = params.get('name', 'unknown')
                    
                    pending_requests.append({
                        'rpc_id': rpc_id,
                        'tool': tool_name,
                        'params': params.get('arguments', {}),
                        'timestamp': block['timestamp'],
                        'request_size': len(json.dumps(body_json)),
                        'block_index': i,
                    })
                    
                    if debug:
                        print(f"    REQ found [{i}] {source}: {tool_name} id={rpc_id}")
        
        if block['direction'] == '<':
            assembled_data = assemble_response_data(blocks, i)
            sse_results = extract_sse_data(assembled_data)
            
            if debug and 'event: message' in block['data'].replace('\\r', ''):
                if not sse_results:
                    print(f"    SSE MISS [{i}]: has 'event: message' but extract_sse_data found nothing")
                    print(f"      assembled: {len(assembled_data)} chars (block data: {len(block['data'])} chars)")
                    print(f"      data preview: {repr(assembled_data[:200])}")
            
            if not sse_results and raw_log and 'event: message' in block['data'].replace('\\r', ''):
                fallback = _raw_fallback_extract(raw_log, blocks, i)
                if fallback:
                    sse_results = [fallback]
                    if debug:
                        print(f"    RAW FALLBACK [{i}]: extracted from raw log")
            
            if debug and sse_results:
                for sr in sse_results:
                    rid = sr.get('id', '?')
                    has_result = 'result' in sr
                    note = " [assembled]" if len(assembled_data) > len(block['data']) else ""
                    print(f"    SSE found [{i}]: id={rid} has_result={has_result}{note}")
            
            for result_json in sse_results:
                rpc_id = result_json.get('id')
                result_data = result_json.get('result')
                
                if rpc_id is None or result_data is None:
                    continue
                
                has_tools = 'tools' in result_data
                has_protocol = 'protocolVersion' in result_data
                
                if has_tools or has_protocol:
                    if debug:
                        print(f"    RESP skip [{i}]: protocol/tools-list response id={rpc_id}")
                    continue
                
                matched_idx = None
                for j, req in enumerate(pending_requests):
                    if req['rpc_id'] == rpc_id:
                        matched_idx = j
                        break
                
                if matched_idx is None:
                    if debug:
                        print(f"    RESP orphan [{i}]: id={rpc_id} no pending request")
                    continue
                
                req = pending_requests.pop(matched_idx)
                
                if debug:
                    print(f"    RESP match [{i}]: id={rpc_id} -> {req['tool']}")
                
                structured = result_data.get('structuredContent', {})
                response_content = structured if structured else result_data
                response_str = json.dumps(response_content)
                
                try:
                    req_time = parse_socat_timestamp(req['timestamp'])
                    resp_time = parse_socat_timestamp(block['timestamp'])
                    duration_ms = int((resp_time - req_time).total_seconds() * 1000)
                except Exception:
                    duration_ms = 0
                
                tool_calls.append({
                    'timestamp': format_timestamp(req['timestamp']),
                    'tool': req['tool'],
                    'request': req['params'],
                    'response': response_content,
                    'duration_ms': duration_ms,
                    'request_size_chars': req['request_size'],
                    'response_size_chars': len(response_str),
                })
    
    if debug and pending_requests:
        print(f"    UNMATCHED requests: {[(r['tool'], r['rpc_id']) for r in pending_requests]}")
    
    return tool_calls

def parse_socat_timestamp(ts_str):
    """Parse socat timestamp: 2026/02/06 20:39:10.000145209"""
    parts = ts_str.split('.')
    if len(parts) == 2:
        micros = parts[1][:6]
        ts_str = f"{parts[0]}.{micros}"
    return datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S.%f")


def format_timestamp(ts_str):
    """Convert socat timestamp to ISO 8601."""
    dt = parse_socat_timestamp(ts_str)
    return dt.replace(tzinfo=timezone.utc).isoformat()


def extract_answer_text(response):
    """Extract the human-readable answer text from a tool response."""
    if not isinstance(response, dict):
        return ''
    
    answer = response.get('answer', '')
    if answer:
        return answer
    
    content = response.get('content', [])
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get('type') == 'text':
                text_val = item.get('text', '')
                try:
                    inner = json.loads(text_val)
                    if isinstance(inner, dict):
                        return inner.get('answer', text_val)
                except (json.JSONDecodeError, TypeError):
                    return text_val
    
    text = response.get('text', '')
    if text:
        return text
    
    if 'prompts' in response and len(response) <= 2:
        return ''
    
    return ''


def write_jsonl(tool_calls, output_path):
    """Write tool calls to JSONL file (Stream 1)."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        for call in tool_calls:
            f.write(json.dumps(call) + '\n')
    
    return len(tool_calls)


def write_extracted_files(tool_calls, extracted_dir):
    """Write notebook_query results as individual text files (Stream 2).
    
    v5: Uses SERAPH signal string parsing with 3-tier routing.
    Falls back to legacy META pattern, then to timestamp naming.
    
    Routing tiers:
      Tier 1 -- TAGGED + KNOWN:   Signal string present, pass type recognized
                                   -> {PROJECT}/phase2/{PASS}/
      Tier 2 -- TAGGED + UNKNOWN: Signal string present, pass type unrecognized
                                   -> _review/
      Tier 3 -- UNTAGGED:         No signal string detected
                                   -> _untagged/
    """
    extracted_dir.mkdir(parents=True, exist_ok=True)
    (extracted_dir / '_untagged').mkdir(exist_ok=True)
    (extracted_dir / '_review').mkdir(exist_ok=True)
    
    count = 0
    for call in tool_calls:
        if call['tool'] != 'notebook_query':
            continue
        
        query_text = call['request'].get('query', '')
        response = call['response']
        
        answer = extract_answer_text(response)
        
        if not answer:
            continue
        
        # === D-024 FIX: Strip socat artifacts from answer ===
        answer = strip_socat_artifacts(answer)
        
        # === SIGNAL STRING PARSING ===
        seraph = parse_seraph_string(query_text)
        meta_match = META_PATTERN.search(query_text) if not seraph else None
        
        # Common metadata
        notebook_id = call['request'].get('notebook_id', 'N/A')
        source_ids = call['request'].get('source_ids', None)
        source_ids_str = ', '.join(source_ids) if source_ids else 'all'
        conversation_id = call['request'].get('conversation_id', None) or 'N/A'
        conv_id_response = ''
        if isinstance(response, dict):
            conv_id_response = response.get('conversation_id', '') or ''
        
        response_chars = len(answer)
        duration = call.get('duration_ms', 'N/A')
        
        try:
            ts = datetime.fromisoformat(call['timestamp'])
            ts_str = ts.strftime('%Y-%m-%d_%H%M%S')
        except Exception:
            ts_str = 'unknown'
        
        if seraph:
            # === TIER 1 or TIER 2: SERAPH signal string present ===
            project = seraph['PROJECT']
            pass_code = seraph['PASS']
            num = seraph['NUM']
            sp = seraph.get('SP', '')
            theme = seraph.get('THEME', '')
            session = seraph.get('SESSION', '')
            config = seraph.get('CONFIG', 'default')
            thread = seraph.get('THREAD', '')
            notes = seraph.get('NOTES', '')
            
            tier, pass_name = classify_pass_type(pass_code)
            
            if sp:
                filename = f"{ts_str}_{project}_SP{sp}_{pass_code}-{num}_notebook-query.txt"
            else:
                filename = f"{ts_str}_{project}_{pass_code}-{num}_notebook-query.txt"
            
            if tier == 'known':
                dest_dir = extracted_dir / project / 'phase2' / pass_code
            else:
                dest_dir = extracted_dir / '_review'
            
            dest_dir.mkdir(parents=True, exist_ok=True)
            filepath = dest_dir / filename
            
            clean_query = strip_seraph_string(query_text)
            
            sp_display = f"SP{sp}" if sp else 'N/A'
            theme_display = theme if theme else 'N/A'
            session_display = session if session else 'N/A'
            tier_display = f"Tier 1 (Tagged + Known)" if tier == 'known' else f"Tier 2 (Tagged + Unknown: {pass_code})"
            
            header_name = filename.replace('.txt', '')
            
            file_content = f"""================================================================================
EXTRACTION: {header_name}
================================================================================
Source Package:  {sp_display}
Pass Type:       {pass_code} ({pass_name})
Pass Number:     {num}
Theme/Focus:     {theme_display}
Project:         {project}
Session:         {session_display}
Routing:         {tier_display}
Query:           {clean_query}
Timestamp:       {call['timestamp']}
Notebook ID:     {notebook_id}
Source IDs:      {source_ids_str}
Conversation ID: {conversation_id if conversation_id != 'N/A' else conv_id_response if conv_id_response else 'N/A'}
Chat Configure:  {config}
Thread:          {thread if thread else 'N/A'}
Notes:           {notes if notes else 'N/A'}
Response Chars:  {response_chars}
Duration:        {duration}ms
================================================================================

{answer}

================================================================================
END OF EXTRACTION
================================================================================
"""
        
        elif meta_match:
            # === LEGACY META FORMAT ===
            sp = meta_match.group('sp')
            ptype = meta_match.group('ptype')
            seq = meta_match.group('seq')
            desc = meta_match.group('desc')
            
            ptype_name = PASS_TYPE_NAMES.get(ptype, ptype)
            clean_query = META_PATTERN.sub('', query_text).strip()
            
            filename = f"{ts_str}_{sp}-{ptype}{seq}-{desc}_notebook-query.txt"
            filepath = extracted_dir / '_untagged' / filename
            
            header_name = filename.replace('.txt', '')
            
            file_content = f"""================================================================================
EXTRACTION: {header_name}
================================================================================
Source Package:  {sp}
Pass Type:       {ptype} ({ptype_name})
Pass Number:     {seq}
Theme/Focus:     {desc}
Routing:         Legacy META format (unrouted)
Query:           {clean_query}
Timestamp:       {call['timestamp']}
Notebook ID:     {notebook_id}
Source IDs:      {source_ids_str}
Conversation ID: {conversation_id if conversation_id != 'N/A' else conv_id_response if conv_id_response else 'N/A'}
Chat Configure:  default
Response Chars:  {response_chars}
Duration:        {duration}ms
================================================================================

{answer}

================================================================================
END OF EXTRACTION
================================================================================
"""
        
        else:
            # === TIER 3: UNTAGGED ===
            filename = f"{ts_str}_notebook-query.txt"
            filepath = extracted_dir / '_untagged' / filename
            clean_query = query_text
            
            header_name = filename.replace('.txt', '')
            
            file_content = f"""================================================================================
EXTRACTION: {header_name}
================================================================================
Source Package:  N/A
Pass Type:       N/A (N/A)
Pass Number:     N/A
Theme/Focus:     Untagged
Routing:         Tier 3 (Untagged)
Query:           {clean_query}
Timestamp:       {call['timestamp']}
Notebook ID:     {notebook_id}
Source IDs:      {source_ids_str}
Conversation ID: {conversation_id if conversation_id != 'N/A' else conv_id_response if conv_id_response else 'N/A'}
Chat Configure:  default
Response Chars:  {response_chars}
Duration:        {duration}ms
================================================================================

{answer}

================================================================================
END OF EXTRACTION
================================================================================
"""
        
        with open(filepath, 'w') as f:
            f.write(file_content)
        
        count += 1
    
    return count


def process_log(date_str=None):
    """Process a single day's traffic log."""
    if date_str is None:
        date_str = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    
    log_path = TRAFFIC_DIR / f"{date_str}.log"
    
    if not log_path.exists():
        print(f"No traffic log found: {log_path}")
        return
    
    print(f"Processing: {log_path}")
    print(f"  Log size: {log_path.stat().st_size:,} bytes")
    
    blocks = parse_socat_log(log_path)
    print(f"  Parsed {len(blocks)} directional blocks")
    
    req_count = sum(1 for b in blocks if b['direction'] == '>')
    resp_count = sum(1 for b in blocks if b['direction'] == '<')
    print(f"  Blocks: {req_count} requests (>), {resp_count} responses (<)")
    
    debug = '--verbose' in sys.argv
    with open(log_path, "r", errors="replace") as f:
        raw_log = f.read()
    tool_calls = correlate_tool_calls(blocks, debug=debug, raw_log=raw_log)
    print(f"  Correlated {len(tool_calls)} tool calls")
    
    if not tool_calls:
        print("  No tool calls found in log.")
        return
    
    tool_counts = {}
    for call in tool_calls:
        name = call['tool']
        tool_counts[name] = tool_counts.get(name, 0) + 1
        resp_chars = call.get('response_size_chars', 0)
        answer_text = extract_answer_text(call['response'])
        print(f"    {name}: response={resp_chars} chars, answer={len(answer_text)} chars")
    print(f"  Tool breakdown: {tool_counts}")
    
    jsonl_path = RAW_DIR / f"{date_str}.jsonl"
    jsonl_count = write_jsonl(tool_calls, jsonl_path)
    print(f"  Stream 1: {jsonl_count} entries -> {jsonl_path}")
    
    query_count = write_extracted_files(tool_calls, EXTRACTED_DIR)
    print(f"  Stream 2: {query_count} notebook_query extractions -> {EXTRACTED_DIR}")
    
    print(f"  Done.")


def main():
    if len(sys.argv) > 1:
        if sys.argv[1] == '--all':
            logs = sorted(TRAFFIC_DIR.glob('*.log'))
            if not logs:
                print(f"No traffic logs found in {TRAFFIC_DIR}")
                return
            print(f"Processing {len(logs)} log files...")
            for log_path in logs:
                date_str = log_path.stem
                process_log(date_str)
        elif sys.argv[1] == '--debug':
            date_str = sys.argv[2] if len(sys.argv) > 2 else datetime.now(timezone.utc).strftime('%Y-%m-%d')
            log_path = TRAFFIC_DIR / f"{date_str}.log"
            blocks = parse_socat_log(log_path)
            for i, b in enumerate(blocks):
                pre = f" pre_data={len(b['pre_data'])}ch" if b['pre_data'] else ""
                has_json = '{' in b['data'] or '{' in b.get('pre_data', '')
                print(f"  [{i:3d}] {b['direction']} {b['timestamp']} len={b['length']} data={len(b['data'])}ch{pre} json={'Y' if has_json else 'N'}")
        else:
            process_log(sys.argv[1])
    else:
        process_log()


if __name__ == '__main__':
    main()
