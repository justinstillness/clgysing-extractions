#!/usr/bin/env python3
"""
MCP Traffic Extraction Script (Component 2) — v6
==================================================
Parses socat -v raw traffic logs into:
  Stream 1: Structured JSONL (all tool calls)
  Stream 2: Clean extracted text files (notebook_query only)

v6 changes: Failure resilience
  - Ghost files for failed extractions (never silently drop a query)
  - Failure taxonomy: NO_RESPONSE, PARTIAL, PARSE_ERROR, EMPTY_ANSWER
  - _FAILED suffix on ghost filenames for easy identification
  - Extraction summary with success/failure counts and breakdown
  - Raw response preview preserved in ghost files for debugging

v5 changes: Signal String (SERAPH) integration
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

TRAFFIC_DIR = Path("/home/ubuntu/mcp-logs/traffic")
RAW_DIR = Path("/home/ubuntu/mcp-logs/raw")
EXTRACTED_DIR = Path("/home/ubuntu/mcp-logs/extracted")

FAIL_NO_RESPONSE = "NO_RESPONSE"
FAIL_EMPTY_ANSWER = "EMPTY_ANSWER"
FAIL_PARTIAL = "PARTIAL"
FAIL_PARSE_ERROR = "PARSE_ERROR"
FAIL_CORRELATION = "CORRELATION_FAILED"

SERAPH_PATTERN = re.compile(r'\[SERAPH:\s*(.+?)\]')
META_PATTERN = re.compile(r'\[META:(?P<sp>SP\d+)\|(?P<ptype>[A-Z]{2})\|(?P<seq>\d+)\|(?P<desc>[^\]]+)\]')

PASS_TYPE_NAMES = {
    'TM': 'Theme Mapping', 'TX': 'Thematic Extraction', 'VX': 'Vocabulary Extraction',
    'TS': 'Thesis String Extraction', 'EV': 'Evaluation Pass', 'GD': 'Gap Detection',
    'GX': 'Gap Extraction', 'CL': 'Classification', 'TL': 'Thesis-Lens Extraction',
    'PE': 'Pre-Extraction Evaluation', 'QC': 'Query Context', 'NB': 'Notebook Administration',
    'GL': 'Glossary Generation', 'CR': 'Cross-Reference Mapping',
    'CE': 'Concept Extraction (deprecated - TX)', 'FP': 'Full Pass (legacy)',
}

SOCAT_ARTIFACT_RE = re.compile(
    r'^[<>]\s+\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+length=\d+\s+from=\d+\s+to=\d+\s*$',
    re.MULTILINE
)
HEADER_RE = re.compile(
    r'([><])\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+length=(\d+)\s+from=(\d+)\s+to=(\d+)'
)

def parse_seraph_string(query_text):
    match = SERAPH_PATTERN.search(query_text)
    if not match: return None
    fields = {}
    for pair in match.group(1).split(','):
        pair = pair.strip()
        if '=' in pair:
            key, value = pair.split('=', 1)
            fields[key.strip().upper()] = value.strip()
    for req in ['PROJECT', 'PASS', 'NUM']:
        if req not in fields: return None
    return fields

def strip_seraph_string(query_text):
    return SERAPH_PATTERN.sub('', query_text).strip()

def strip_socat_artifacts(text):
    return SOCAT_ARTIFACT_RE.sub('', text)

def classify_pass_type(pass_code):
    if pass_code in PASS_TYPE_NAMES: return ('known', PASS_TYPE_NAMES[pass_code])
    return ('unknown', pass_code)

def classify_failure(call, answer, response):
    response_chars = call.get('response_size_chars', 0)
    if response_chars <= 20:
        return (FAIL_NO_RESPONSE, f"Response was {response_chars} chars -- likely timeout or NotebookLM failure")
    if response and not answer:
        if isinstance(response, dict):
            raw_answer = response.get('answer', None)
            if raw_answer is not None and raw_answer == '':
                return (FAIL_EMPTY_ANSWER, f"Answer field empty. Response size: {response_chars} chars")
            status = response.get('status', '')
            if status and status != 'success':
                return (FAIL_PARSE_ERROR, f"Status was '{status}'. Response size: {response_chars} chars")
        return (FAIL_PARSE_ERROR, f"Response had {response_chars} chars but answer extraction failed")
    if answer and len(answer) < 20 and response_chars > 500:
        return (FAIL_PARTIAL, f"Answer only {len(answer)} chars from {response_chars}-char response")
    return (FAIL_NO_RESPONSE, f"No usable answer. Response size: {response_chars} chars")

def parse_socat_log(log_path):
    raw_text = open(log_path, 'r', errors='replace').read()
    headers = list(HEADER_RE.finditer(raw_text))
    if not headers: return []
    blocks = []
    for i, m in enumerate(headers):
        direction, timestamp, length = m.group(1), m.group(2), int(m.group(3))
        data_start = m.end()
        nl = raw_text.find('\n', data_start)
        data_start_line = data_start if nl == -1 else nl + 1
        data_end = headers[i+1].start() if i+1 < len(headers) else len(raw_text)
        pre_data = ''
        line_start = raw_text.rfind('\n', 0, m.start())
        line_start = 0 if line_start == -1 else line_start + 1
        if line_start < m.start(): pre_data = raw_text[line_start:m.start()]
        blocks.append({'direction': direction, 'timestamp': timestamp, 'length': length,
                       'data': raw_text[data_start_line:data_end], 'pre_data': pre_data})
    return blocks

def clean_socat_text(text): return text.replace('\\r', '')

def extract_json_from_text(text):
    start = text.find('{')
    if start == -1: return None, -1
    depth, in_string, escape_next = 0, False, False
    for i in range(start, len(text)):
        c = text[i]
        if escape_next: escape_next = False; continue
        if c == '\\' and in_string: escape_next = True; continue
        if c == '"' and not escape_next: in_string = not in_string; continue
        if in_string: continue
        if c == '{': depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                try: return json.loads(text[start:i+1]), i+1
                except json.JSONDecodeError: return None, -1
    return None, -1

def extract_all_json_from_text(text):
    results, pos = [], 0
    while pos < len(text):
        obj, end_pos = extract_json_from_text(text[pos:])
        if obj is None: break
        results.append(obj); pos += end_pos
    return results

def extract_sse_data(text):
    cleaned = clean_socat_text(text)
    results = []
    for line in cleaned.split('\n'):
        line = line.strip()
        data_idx = line.find('data: {')
        if data_idx > 0:
            prefix = line[:data_idx]
            if all(c in '0123456789abcdefABCDEF' for c in prefix): line = line[data_idx:]
        elif data_idx == -1: continue
        if line.startswith('data: '):
            payload = line[6:]
            if payload.startswith('{'):
                normalized = payload
                prev = None
                while prev != normalized: prev = normalized; normalized = normalized.replace('\\\\', '\\')
                try: results.append(json.loads(normalized))
                except json.JSONDecodeError:
                    obj, _ = extract_json_from_text(normalized)
                    if obj: results.append(obj)
    if not results and '"structuredContent":{' in text:
        fallback = _extract_structured_content_fallback(text)
        if fallback: results.append(fallback)
    return results

def _extract_structured_content_fallback(text):
    rpc_id = None
    id_match = re.search(r'"id"\s*:\s*(\d+)', text)
    if id_match: rpc_id = int(id_match.group(1))
    sc_pos = text.find('"structuredContent":{')
    if sc_pos < 0: return None
    answer_start = text.find('"answer":"', sc_pos)
    if answer_start < 0: return None
    answer_start += len('"answer":"')
    answer_end = -1
    for end_marker in ['","conversation_id":"', '","sources_used":']:
        pos = text.find(end_marker, answer_start)
        if pos > 0 and (answer_end < 0 or pos < answer_end): answer_end = pos
    if answer_end < 0: return None
    answer = text[answer_start:answer_end].replace('\\n', '\n').replace('\\r', '').replace('\\"', '"')
    conv_id = None
    conv_match = re.search(r'"conversation_id"\s*:\s*"([^"]+)"', text[sc_pos:])
    if conv_match: conv_id = conv_match.group(1)
    return {'id': rpc_id, 'result': {'structuredContent': {'status': 'success', 'answer': answer, 'conversation_id': conv_id or '', 'sources_used': []}}}

def _raw_fallback_extract(raw_log, blocks, block_idx):
    block_ts = blocks[block_idx]['timestamp']
    block_raw_pos = raw_log.find(block_ts)
    if block_raw_pos < 0: return None
    end_raw_pos = len(raw_log)
    for j in range(block_idx + 1, min(block_idx + 20, len(blocks))):
        if blocks[j]['direction'] == '>':
            next_pos = raw_log.find(blocks[j]['timestamp'], block_raw_pos + 1)
            if next_pos > 0: end_raw_pos = next_pos; break
    region = raw_log[block_raw_pos:end_raw_pos]
    sc_pos = region.find('"structuredContent":{')
    if sc_pos < 0: return None
    ans_pos = region.find('"answer":"', sc_pos)
    if ans_pos < 0: return None
    ans_start = ans_pos + len('"answer":"')
    ans_end = -1
    for marker in ['","conversation_id":"', '","sources_used":']:
        pos = region.find(marker, ans_start)
        if pos > 0 and (ans_end < 0 or pos < ans_end): ans_end = pos
    if ans_end < 0: return None
    answer = region[ans_start:ans_end].replace('\\n', '\n').replace('\\r', '').replace('\\"', '"')
    conv_id = ''
    conv_match = re.search(r'"conversation_id"\s*:\s*"([^"]+)"', region[sc_pos:])
    if conv_match: conv_id = conv_match.group(1)
    rpc_id = None
    id_match = re.search(r'"id"\s*:\s*(\d+)', region[:sc_pos])
    if id_match: rpc_id = int(id_match.group(1))
    return {'id': rpc_id, 'result': {'structuredContent': {'status': 'success', 'answer': answer, 'conversation_id': conv_id, 'sources_used': []}}}

def assemble_response_data(blocks, start_idx):
    block = blocks[start_idx]
    assembled = block['data']
    for j in range(start_idx + 1, min(start_idx + 10, len(blocks))):
        next_block = blocks[j]
        if next_block['pre_data']: assembled += next_block['pre_data']
        if next_block['direction'] == '>': break
        if next_block['data'].strip() and 'event: message' in next_block['data']: break
        if next_block['data'].strip() in ('', '0', '\\r', '\\r\\n\\r\\n'): continue
        if len(next_block['data'].strip()) > 20: break
    return assembled

def correlate_tool_calls(blocks, debug=False, raw_log=None):
    tool_calls, pending_requests = [], []
    for i, block in enumerate(blocks):
        if block['direction'] == '>':
            cleaned = clean_socat_text(block['data'])
            for body_json in extract_all_json_from_text(cleaned):
                method, rpc_id = body_json.get('method', ''), body_json.get('id')
                if method == 'tools/call' and rpc_id is not None:
                    params = body_json.get('params', {})
                    pending_requests.append({'rpc_id': rpc_id, 'tool': params.get('name', 'unknown'),
                        'params': params.get('arguments', {}), 'timestamp': block['timestamp'],
                        'request_size': len(json.dumps(body_json)), 'block_index': i})
                    if debug: print(f"    REQ found [{i}]: {params.get('name','unknown')} id={rpc_id}")
        if block['direction'] == '<':
            assembled_data = assemble_response_data(blocks, i)
            sse_results = extract_sse_data(assembled_data)
            if debug and 'event: message' in block['data'].replace('\\r', '') and not sse_results:
                print(f"    SSE MISS [{i}]: assembled={len(assembled_data)} chars")
            if not sse_results and raw_log and 'event: message' in block['data'].replace('\\r', ''):
                fallback = _raw_fallback_extract(raw_log, blocks, i)
                if fallback: sse_results = [fallback]
                if debug and fallback: print(f"    RAW FALLBACK [{i}]")
            for result_json in sse_results:
                rpc_id, result_data = result_json.get('id'), result_json.get('result')
                if rpc_id is None or result_data is None: continue
                if 'tools' in result_data or 'protocolVersion' in result_data: continue
                matched_idx = None
                for j, req in enumerate(pending_requests):
                    if req['rpc_id'] == rpc_id: matched_idx = j; break
                if matched_idx is None: continue
                req = pending_requests.pop(matched_idx)
                structured = result_data.get('structuredContent', {})
                response_content = structured if structured else result_data
                try:
                    duration_ms = int((parse_socat_timestamp(block['timestamp']) - parse_socat_timestamp(req['timestamp'])).total_seconds() * 1000)
                except: duration_ms = 0
                tool_calls.append({'timestamp': format_timestamp(req['timestamp']), 'tool': req['tool'],
                    'request': req['params'], 'response': response_content, 'duration_ms': duration_ms,
                    'request_size_chars': req['request_size'], 'response_size_chars': len(json.dumps(response_content))})
    if debug and pending_requests:
        print(f"    UNMATCHED: {[(r['tool'], r['rpc_id']) for r in pending_requests]}")
    return tool_calls

def parse_socat_timestamp(ts_str):
    parts = ts_str.split('.')
    if len(parts) == 2: ts_str = f"{parts[0]}.{parts[1][:6]}"
    return datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S.%f")

def format_timestamp(ts_str):
    return parse_socat_timestamp(ts_str).replace(tzinfo=timezone.utc).isoformat()

def extract_answer_text(response):
    if not isinstance(response, dict): return ''
    answer = response.get('answer', '')
    if answer: return answer
    content = response.get('content', [])
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get('type') == 'text':
                text_val = item.get('text', '')
                try:
                    inner = json.loads(text_val)
                    if isinstance(inner, dict): return inner.get('answer', text_val)
                except: return text_val
    text = response.get('text', '')
    if text: return text
    if 'prompts' in response and len(response) <= 2: return ''
    return ''

def write_jsonl(tool_calls, output_path):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        for call in tool_calls: f.write(json.dumps(call) + '\n')
    return len(tool_calls)

def _build_metadata(call, seraph, meta_match, answer, failure_info=None):
    query_text = call['request'].get('query', '')
    response = call['response']
    notebook_id = call['request'].get('notebook_id', 'N/A')
    source_ids = call['request'].get('source_ids', None)
    source_ids_str = ', '.join(source_ids) if source_ids else 'all'
    conversation_id = call['request'].get('conversation_id', None) or 'N/A'
    conv_id_response = response.get('conversation_id', '') or '' if isinstance(response, dict) else ''
    try: ts_str = datetime.fromisoformat(call['timestamp']).strftime('%Y-%m-%d_%H%M%S')
    except: ts_str = 'unknown'
    meta = {'ts_str': ts_str, 'notebook_id': notebook_id, 'source_ids_str': source_ids_str,
        'conversation_id': conversation_id if conversation_id != 'N/A' else conv_id_response or 'N/A',
        'response_chars': len(answer) if answer else 0, 'duration': call.get('duration_ms', 'N/A'),
        'timestamp_iso': call['timestamp'], 'failure_info': failure_info}
    if seraph:
        tier, pass_name = classify_pass_type(seraph['PASS'])
        meta.update({'tag_type': 'seraph', 'project': seraph['PROJECT'], 'pass_code': seraph['PASS'],
            'num': seraph['NUM'], 'sp': seraph.get('SP', ''), 'theme': seraph.get('THEME', ''),
            'session': seraph.get('SESSION', ''), 'config': seraph.get('CONFIG', 'default'),
            'thread': seraph.get('THREAD', ''), 'notes': seraph.get('NOTES', ''),
            'tier': tier, 'pass_name': pass_name, 'clean_query': strip_seraph_string(query_text)})
    elif meta_match:
        meta.update({'tag_type': 'legacy_meta', 'sp': meta_match.group('sp'), 'pass_code': meta_match.group('ptype'),
            'num': meta_match.group('seq'), 'theme': meta_match.group('desc'),
            'pass_name': PASS_TYPE_NAMES.get(meta_match.group('ptype'), meta_match.group('ptype')),
            'clean_query': META_PATTERN.sub('', query_text).strip()})
    else:
        meta.update({'tag_type': 'untagged', 'clean_query': query_text})
    return meta

def _build_filename(meta, is_ghost=False):
    ts_str, sfx = meta['ts_str'], '_FAILED' if is_ghost else ''
    if meta['tag_type'] == 'seraph':
        sp = meta.get('sp', '')
        if sp: return f"{ts_str}_{meta['project']}_SP{sp}_{meta['pass_code']}-{meta['num']}{sfx}_notebook-query.txt"
        return f"{ts_str}_{meta['project']}_{meta['pass_code']}-{meta['num']}{sfx}_notebook-query.txt"
    elif meta['tag_type'] == 'legacy_meta':
        return f"{ts_str}_{meta['sp']}-{meta['pass_code']}{meta['num']}-{meta['theme']}{sfx}_notebook-query.txt"
    return f"{ts_str}{sfx}_notebook-query.txt"

def _resolve_dest_dir(meta, extracted_dir, is_ghost=False):
    if meta['tag_type'] == 'seraph':
        if is_ghost:
            dest = extracted_dir / '_failed'
            if meta['tier'] == 'known': dest = dest / meta['project'] / meta['pass_code']
            return dest
        if meta['tier'] == 'known': return extracted_dir / meta['project'] / 'phase2' / meta['pass_code']
        return extracted_dir / '_review'
    if is_ghost: return extracted_dir / '_failed'
    return extracted_dir / '_untagged'

def _write_successful_file(filepath, meta, answer):
    hn = filepath.name.replace('.txt', '')
    if meta['tag_type'] == 'seraph':
        sp_d = f"SP{meta['sp']}" if meta.get('sp') else 'N/A'
        tier_d = "Tier 1 (Tagged + Known)" if meta['tier'] == 'known' else f"Tier 2 (Tagged + Unknown: {meta['pass_code']})"
        hdr = f"Source Package:  {sp_d}\nPass Type:       {meta['pass_code']} ({meta['pass_name']})\nPass Number:     {meta['num']}\nTheme/Focus:     {meta.get('theme') or 'N/A'}\nProject:         {meta['project']}\nSession:         {meta.get('session') or 'N/A'}\nRouting:         {tier_d}\nQuery:           {meta['clean_query']}\nTimestamp:       {meta['timestamp_iso']}\nNotebook ID:     {meta['notebook_id']}\nSource IDs:      {meta['source_ids_str']}\nConversation ID: {meta['conversation_id']}\nChat Configure:  {meta.get('config', 'default')}\nThread:          {meta.get('thread') or 'N/A'}\nNotes:           {meta.get('notes') or 'N/A'}\nResponse Chars:  {meta['response_chars']}\nDuration:        {meta['duration']}ms"
    elif meta['tag_type'] == 'legacy_meta':
        hdr = f"Source Package:  {meta['sp']}\nPass Type:       {meta['pass_code']} ({meta['pass_name']})\nPass Number:     {meta['num']}\nTheme/Focus:     {meta['theme']}\nRouting:         Legacy META format (unrouted)\nQuery:           {meta['clean_query']}\nTimestamp:       {meta['timestamp_iso']}\nNotebook ID:     {meta['notebook_id']}\nSource IDs:      {meta['source_ids_str']}\nConversation ID: {meta['conversation_id']}\nChat Configure:  default\nResponse Chars:  {meta['response_chars']}\nDuration:        {meta['duration']}ms"
    else:
        hdr = f"Source Package:  N/A\nPass Type:       N/A (N/A)\nPass Number:     N/A\nTheme/Focus:     Untagged\nRouting:         Tier 3 (Untagged)\nQuery:           {meta['clean_query']}\nTimestamp:       {meta['timestamp_iso']}\nNotebook ID:     {meta['notebook_id']}\nSource IDs:      {meta['source_ids_str']}\nConversation ID: {meta['conversation_id']}\nChat Configure:  default\nResponse Chars:  {meta['response_chars']}\nDuration:        {meta['duration']}ms"
    with open(filepath, 'w') as f:
        f.write(f"{'='*80}\nEXTRACTION: {hn}\n{'='*80}\n{hdr}\n{'='*80}\n\n{answer}\n\n{'='*80}\nEND OF EXTRACTION\n{'='*80}\n")

def _write_ghost_file(filepath, meta, response):
    hn = filepath.name.replace('.txt', '')
    fc, fd = meta['failure_info']
    raw_preview = ''
    if response:
        raw_str = json.dumps(response)
        raw_preview = raw_str[:500]
        if len(raw_str) > 500: raw_preview += f'\n... [{len(raw_str)-500} more chars]'
    if meta['tag_type'] == 'seraph':
        sp_d = f"SP{meta['sp']}" if meta.get('sp') else 'N/A'
        tier_d = "Tier 1 (Tagged + Known)" if meta['tier'] == 'known' else f"Tier 2 (Tagged + Unknown: {meta['pass_code']})"
        tag_hdr = f"Source Package:  {sp_d}\nPass Type:       {meta['pass_code']} ({meta['pass_name']})\nPass Number:     {meta['num']}\nTheme/Focus:     {meta.get('theme') or 'N/A'}\nProject:         {meta['project']}\nSession:         {meta.get('session') or 'N/A'}\nWould-Be Route:  {tier_d}"
    elif meta['tag_type'] == 'legacy_meta':
        tag_hdr = f"Source Package:  {meta['sp']}\nPass Type:       {meta['pass_code']} ({meta['pass_name']})\nPass Number:     {meta['num']}\nTheme/Focus:     {meta['theme']}\nWould-Be Route:  Legacy META format"
    else:
        tag_hdr = "Source Package:  N/A\nPass Type:       N/A\nWould-Be Route:  Tier 3 (Untagged)"
    with open(filepath, 'w') as f:
        f.write(f"{'='*80}\nEXTRACTION: {hn} [FAILED]\n{'='*80}\nStatus:          {fc}\nError Detail:    {fd}\n{tag_hdr}\nQuery:           {meta['clean_query']}\nTimestamp:       {meta['timestamp_iso']}\nNotebook ID:     {meta['notebook_id']}\nSource IDs:      {meta['source_ids_str']}\nConversation ID: {meta['conversation_id']}\nResponse Chars:  {meta['response_chars']}\nDuration:        {meta['duration']}ms\n{'='*80}\n\nNO CONTENT EXTRACTED -- SEE ERROR DETAIL ABOVE\n\nRaw Response Preview:\n{raw_preview or '(no response data captured)'}\n\n{'='*80}\nEND OF GHOST EXTRACTION\n{'='*80}\n")

def write_extracted_files(tool_calls, extracted_dir):
    extracted_dir.mkdir(parents=True, exist_ok=True)
    for d in ['_untagged', '_review', '_failed']: (extracted_dir / d).mkdir(exist_ok=True)
    success_count, ghost_count, failure_breakdown, skipped = 0, 0, {}, 0
    for call in tool_calls:
        if call['tool'] != 'notebook_query': skipped += 1; continue
        query_text, response = call['request'].get('query', ''), call['response']
        answer = extract_answer_text(response)
        if answer: answer = strip_socat_artifacts(answer)
        seraph = parse_seraph_string(query_text)
        meta_match = META_PATTERN.search(query_text) if not seraph else None
        if answer and len(answer.strip()) > 0:
            meta = _build_metadata(call, seraph, meta_match, answer)
            dest_dir = _resolve_dest_dir(meta, extracted_dir, is_ghost=False)
            dest_dir.mkdir(parents=True, exist_ok=True)
            _write_successful_file(dest_dir / _build_filename(meta), meta, answer)
            success_count += 1
        else:
            fi = classify_failure(call, answer, response)
            meta = _build_metadata(call, seraph, meta_match, answer, failure_info=fi)
            dest_dir = _resolve_dest_dir(meta, extracted_dir, is_ghost=True)
            dest_dir.mkdir(parents=True, exist_ok=True)
            _write_ghost_file(dest_dir / _build_filename(meta, is_ghost=True), meta, response)
            ghost_count += 1; failure_breakdown[fi[0]] = failure_breakdown.get(fi[0], 0) + 1
    return {'success': success_count, 'failed': ghost_count, 'failure_breakdown': failure_breakdown,
            'total_queries': success_count + ghost_count, 'skipped_non_query': skipped}

def process_log(date_str=None):
    if date_str is None: date_str = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    log_path = TRAFFIC_DIR / f"{date_str}.log"
    if not log_path.exists(): print(f"No traffic log found: {log_path}"); return
    print(f"Processing: {log_path}")
    print(f"  Log size: {log_path.stat().st_size:,} bytes")
    blocks = parse_socat_log(log_path)
    print(f"  Parsed {len(blocks)} directional blocks")
    req_count = sum(1 for b in blocks if b['direction'] == '>')
    resp_count = sum(1 for b in blocks if b['direction'] == '<')
    print(f"  Blocks: {req_count} requests (>), {resp_count} responses (<)")
    debug = '--verbose' in sys.argv
    with open(log_path, "r", errors="replace") as f: raw_log = f.read()
    tool_calls = correlate_tool_calls(blocks, debug=debug, raw_log=raw_log)
    print(f"  Correlated {len(tool_calls)} tool calls")
    if not tool_calls: print("  No tool calls found."); return
    tool_counts = {}
    for call in tool_calls:
        name = call['tool']; tool_counts[name] = tool_counts.get(name, 0) + 1
        print(f"    {name}: response={call.get('response_size_chars',0)} chars, answer={len(extract_answer_text(call['response']))} chars")
    print(f"  Tool breakdown: {tool_counts}")
    jsonl_path = RAW_DIR / f"{date_str}.jsonl"
    print(f"  Stream 1: {write_jsonl(tool_calls, jsonl_path)} entries -> {jsonl_path}")
    summary = write_extracted_files(tool_calls, EXTRACTED_DIR)
    total, success, failed = summary['total_queries'], summary['success'], summary['failed']
    if failed > 0:
        bd = ', '.join(f"{c} {k}" for k, c in sorted(summary['failure_breakdown'].items()))
        print(f"  Stream 2: {total} notebook_query extractions -> {EXTRACTED_DIR}")
        print(f"            {success} successful, {failed} FAILED [{bd}]")
        print(f"            Ghost files written to _failed/")
    else:
        print(f"  Stream 2: {total} notebook_query extractions -> {EXTRACTED_DIR}")
        print(f"            All {success} successful")
    print(f"  Done.")

def main():
    if len(sys.argv) > 1:
        if sys.argv[1] == '--all':
            logs = sorted(TRAFFIC_DIR.glob('*.log'))
            if not logs: print(f"No traffic logs in {TRAFFIC_DIR}"); return
            print(f"Processing {len(logs)} log files...")
            for lp in logs: process_log(lp.stem)
        elif sys.argv[1] == '--debug':
            ds = sys.argv[2] if len(sys.argv) > 2 else datetime.now(timezone.utc).strftime('%Y-%m-%d')
            blocks = parse_socat_log(TRAFFIC_DIR / f"{ds}.log")
            for i, b in enumerate(blocks):
                pre = f" pre={len(b['pre_data'])}ch" if b['pre_data'] else ""
                print(f"  [{i:3d}] {b['direction']} {b['timestamp']} len={b['length']} data={len(b['data'])}ch{pre}")
        else: process_log(sys.argv[1])
    else: process_log()

if __name__ == '__main__': main()
