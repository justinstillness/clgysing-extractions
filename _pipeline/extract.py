#!/usr/bin/env python3
"""
MCP Traffic Extraction Script (Component 2) — v2
==================================================
Parses socat -v raw traffic logs into:
  Stream 1: Structured JSONL (all tool calls)
  Stream 2: Clean extracted text files (notebook_query only)

v2 changes: Rewritten parsing for real socat -v format where:
  - JSON body and next block header can be on the SAME line
  - Literal \r appears as two characters: backslash + r
  - Responses span multiple < blocks
  - Multiple MCP sessions reuse JSON-RPC IDs

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

# Meta-tag pattern: [META:SP##|TYPE|SEQ|Descriptor]
META_PATTERN = re.compile(
    r'\[META:(?P<sp>SP\d+)\|(?P<ptype>[A-Z]{2})\|(?P<seq>\d+)\|(?P<desc>[^\]]+)\]'
)

# Pass type full names
PASS_TYPE_NAMES = {
    'TM': 'Theme Mapping',
    'TX': 'Thematic Extraction',
    'GD': 'Gap Detection',
    'GX': 'Gap Extraction',
    'FP': 'Full Pass',
    'PE': 'Pre-Extraction Evaluation',
    'GL': 'Glossary Extraction',
    'TS': 'Thesis String Extraction',
    'VX': 'Vocabulary Extraction',
    'EV': 'Evaluation',
}

# Block header pattern - matches both start-of-line AND mid-line occurrences
# Example: > 2026/02/06 20:39:10.000145209  length=959 from=0 to=958
# Example: ...json}< 2026/02/06 20:39:10.000348504  length=270 from=180 to=449
HEADER_RE = re.compile(
    r'([><])\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+length=(\d+)\s+from=(\d+)\s+to=(\d+)'
)


def parse_socat_log(log_path):
    """Parse a socat -v log file into a list of directional blocks.
    
    Key insight: socat -v can glue the end of one block's data directly to
    the next block's header ON THE SAME LINE. Example:
    
      {"method":"tools/call",...,"id":1}< 2026/02/06 20:41:45.000687  length=270 from=1646 to=1915
    
    The JSON body ends with } and the < header starts immediately after.
    We must split these correctly.
    """
    raw_text = open(log_path, 'r', errors='replace').read()
    
    # Find all block headers with their positions
    headers = list(HEADER_RE.finditer(raw_text))
    
    if not headers:
        return []
    
    blocks = []
    for i, m in enumerate(headers):
        direction = m.group(1)
        timestamp = m.group(2)
        length = int(m.group(3))
        
        # Data starts after the header line
        data_start = m.end()
        # Skip to next line after header
        nl = raw_text.find('\n', data_start)
        if nl == -1:
            data_start_line = data_start
        else:
            data_start_line = nl + 1
        
        # Data ends at next header, or at any text before it on the same line
        if i + 1 < len(headers):
            next_header_start = headers[i + 1].start()
            data_end = next_header_start
        else:
            data_end = len(raw_text)
        
        # Also capture any data BEFORE this header on the same line
        # (this is the key: JSON body glued to next < header)
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
            'pre_data': pre_data,  # data before header on same line
        })
    
    return blocks


def clean_socat_text(text):
    """Clean socat -v text: remove literal \\r sequences."""
    # socat -v logs \r as literal two chars: backslash + r
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
    """Extract ALL JSON objects from text (for SSE with multiple data: lines)."""
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
    """Extract JSON from SSE format in response blocks.
    
    v4: Handles chunk-size prefixes, iterative backslash normalization,
    and falls back to regex extraction of structuredContent for responses
    that span multiple socat blocks with deep escape nesting.
    """
    cleaned = clean_socat_text(text)
    
    results = []
    for line in cleaned.split('\n'):
        line = line.strip()
        
        # Strip leading hex chunk-size prefix if present
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
    
    # FALLBACK: If no results but text contains structuredContent,
    # extract directly via string boundary matching. Handles multi-block
    # responses where JSON parsing fails due to socat escape depth.
    if not results and '"structuredContent":{' in text:
        fallback = _extract_structured_content_fallback(text)
        if fallback:
            results.append(fallback)
    
    return results


def _extract_structured_content_fallback(text):
    """Fallback extraction when normal SSE JSON parsing fails.
    
    Extracts answer from structuredContent via string boundaries.
    Returns synthetic result dict matching expected downstream format.
    """
    import re
    
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
    """Extract answer from raw log when block-based SSE parsing fails.
    
    Finds the raw byte range from the response block header to the
    next request (>) block header, then extracts structuredContent
    answer via string boundary matching.
    """
    import re
    
    block_ts = blocks[block_idx]['timestamp']
    block_raw_pos = raw_log.find(block_ts)
    if block_raw_pos < 0:
        return None
    
    # Find next request block position as end boundary
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
    """Assemble complete SSE response data from potentially split blocks.
    
    Socat splits large responses across block boundaries. The continuation
    data appears in the pre_data field of subsequent blocks. This function
    concatenates block data with continuation pre_data to reconstruct the
    full SSE payload.
    """
    block = blocks[start_idx]
    assembled = block['data']
    
    # Check subsequent blocks for continuation pre_data
    for j in range(start_idx + 1, min(start_idx + 10, len(blocks))):
        next_block = blocks[j]
        
        # If next block has pre_data, it's continuation of our response
        if next_block['pre_data']:
            assembled += next_block['pre_data']
        
        # If next block is a > (request) direction, stop
        if next_block['direction'] == '>':
            break
        
        # If next block has substantial data with a new SSE frame, stop
        if next_block['data'].strip() and 'event: message' in next_block['data']:
            break
        
        # If next block is just whitespace/chunk-end markers, continue
        if next_block['data'].strip() in ('', '0', '\\r', '\\r\\n\\r\\n'):
            continue
        
        # If we see actual new content, stop
        if len(next_block['data'].strip()) > 20:
            break
    
    return assembled


def correlate_tool_calls(blocks, debug=False, raw_log=None):
    """Correlate request/response blocks into tool call records.
    
    v4: Uses assemble_response_data() to reconstruct SSE responses that
    socat splits across multiple block boundaries.
    """
    tool_calls = []
    pending_requests = []
    
    for i, block in enumerate(blocks):
        # === REQUESTS ===
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
        
        # === RESPONSES ===
        if block['direction'] == '<':
            assembled_data = assemble_response_data(blocks, i)
            sse_results = extract_sse_data(assembled_data)
            
            if debug and 'event: message' in block['data'].replace('\\r', ''):
                if not sse_results:
                    print(f"    SSE MISS [{i}]: has 'event: message' but extract_sse_data found nothing")
                    print(f"      assembled: {len(assembled_data)} chars (block data: {len(block['data'])} chars)")
                    print(f"      data preview: {repr(assembled_data[:200])}")
            
            # Raw log fallback for multi-block responses with deep escape nesting
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
    """Extract the human-readable answer text from a tool response.
    
    NotebookLM notebook_query responses have this structure:
      structuredContent: {
        "answer": "The actual text...",
        "conversation_id": "...",
        "sources": [...]
      }
    
    OR in content array format:
      content: [{"type": "text", "text": "{\"answer\": \"...\"}"}]
    """
    if not isinstance(response, dict):
        return ''
    
    # Direct answer field (structuredContent was already extracted)
    answer = response.get('answer', '')
    if answer:
        return answer
    
    # Content array format
    content = response.get('content', [])
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get('type') == 'text':
                text_val = item.get('text', '')
                # Try parsing as JSON (nested structure)
                try:
                    inner = json.loads(text_val)
                    if isinstance(inner, dict):
                        return inner.get('answer', text_val)
                except (json.JSONDecodeError, TypeError):
                    return text_val
    
    # Fallback: if there's a 'text' field directly
    text = response.get('text', '')
    if text:
        return text
    
    # Last resort: dump the whole thing (but skip if it's just metadata)
    if 'prompts' in response and len(response) <= 2:
        return ''  # Empty response (just prompts: [])
    
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
    
    Uses meta-tag parsing for file naming, falls back to timestamp naming.
    """
    extracted_dir.mkdir(parents=True, exist_ok=True)
    (extracted_dir / '_untagged').mkdir(exist_ok=True)
    
    count = 0
    for call in tool_calls:
        if call['tool'] != 'notebook_query':
            continue
        
        query_text = call['request'].get('query', '')
        response = call['response']
        
        # Get the answer text
        answer = extract_answer_text(response)
        
        if not answer:
            continue
        
        # Parse meta-tag for file naming
        meta_match = META_PATTERN.search(query_text)
        
        if meta_match:
            sp = meta_match.group('sp')
            ptype = meta_match.group('ptype')
            seq = meta_match.group('seq')
            desc = meta_match.group('desc')
            
            # Create source package directory
            sp_dir = extracted_dir / sp / 'pass1'
            sp_dir.mkdir(parents=True, exist_ok=True)
            
            filename = f"{sp}-{ptype}{seq}-{desc}.txt"
            filepath = sp_dir / filename
            
            # Strip meta-tag from query for clean display
            clean_query = META_PATTERN.sub('', query_text).strip()
            
            ptype_name = PASS_TYPE_NAMES.get(ptype, ptype)
        else:
            # Fallback: timestamp-based naming
            try:
                ts = datetime.fromisoformat(call['timestamp'])
                ts_str = ts.strftime('%Y-%m-%d_%H%M%S')
            except Exception:
                ts_str = 'unknown'
            
            filename = f"{ts_str}_notebook-query.txt"
            filepath = extracted_dir / '_untagged' / filename
            clean_query = query_text
            sp = 'N/A'
            ptype = 'N/A'
            ptype_name = 'N/A'
            seq = 'N/A'
            desc = 'Untagged Query'
        
        # Build extracted file per spec Section 8.1
        notebook_id = call['request'].get('notebook_id', 'N/A')
        source_ids = call['request'].get('source_ids', None)
        source_ids_str = ', '.join(source_ids) if source_ids else 'all'
        conversation_id = call['request'].get('conversation_id', None) or 'N/A'
        conv_id_response = ''
        if isinstance(response, dict):
            conv_id_response = response.get('conversation_id', '') or ''
        
        header_name = filename.replace('.txt', '')
        response_chars = len(answer)
        duration = call.get('duration_ms', 'N/A')
        
        file_content = f"""================================================================================
EXTRACTION: {header_name}
================================================================================
Source Package:  {sp if meta_match else 'N/A'}
Pass Type:       {ptype} ({ptype_name})
Pass Number:     {seq}
Theme/Focus:     {desc if meta_match else 'Untagged'}
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
    
    # Step 1: Parse socat log into blocks
    blocks = parse_socat_log(log_path)
    print(f"  Parsed {len(blocks)} directional blocks")
    
    # Debug: show block direction summary
    req_count = sum(1 for b in blocks if b['direction'] == '>')
    resp_count = sum(1 for b in blocks if b['direction'] == '<')
    print(f"  Blocks: {req_count} requests (>), {resp_count} responses (<)")
    
    # Step 2: Correlate into tool calls
    debug = '--verbose' in sys.argv
    # Read raw log for fallback extraction
    with open(log_path, "r", errors="replace") as f:
        raw_log = f.read()
    tool_calls = correlate_tool_calls(blocks, debug=debug, raw_log=raw_log)
    print(f"  Correlated {len(tool_calls)} tool calls")
    
    if not tool_calls:
        print("  No tool calls found in log.")
        return
    
    # Print summary
    tool_counts = {}
    for call in tool_calls:
        name = call['tool']
        tool_counts[name] = tool_counts.get(name, 0) + 1
        # Show response size for debugging
        resp_chars = call.get('response_size_chars', 0)
        answer_text = extract_answer_text(call['response'])
        print(f"    {name}: response={resp_chars} chars, answer={len(answer_text)} chars")
    print(f"  Tool breakdown: {tool_counts}")
    
    # Step 3: Write JSONL (Stream 1)
    jsonl_path = RAW_DIR / f"{date_str}.jsonl"
    jsonl_count = write_jsonl(tool_calls, jsonl_path)
    print(f"  Stream 1: {jsonl_count} entries -> {jsonl_path}")
    
    # Step 4: Write extracted files (Stream 2)
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
            # Debug mode: show raw block info
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
