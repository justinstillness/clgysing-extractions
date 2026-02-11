#!/usr/bin/env python3
"""
Transcript Receiver v0.1
Simple web form to paste and save Claude transcripts.
Saves to local filesystem for Chronicler to pick up.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
from datetime import datetime
import os
import json
import html

SAVE_DIR = "/home/ubuntu/transcripts-incoming"
PORT = 8096

os.makedirs(SAVE_DIR, exist_ok=True)

HTML_FORM = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Transcript Receiver</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #1a1a1a; color: #e0e0e0;
    padding: 16px; max-width: 800px; margin: 0 auto;
  }
  h1 { font-size: 1.3rem; margin-bottom: 12px; color: #fff; }
  .info { font-size: 0.85rem; color: #888; margin-bottom: 16px; }
  label { display: block; font-size: 0.9rem; margin-bottom: 4px; color: #bbb; }
  input[type=text] {
    width: 100%%; padding: 10px; margin-bottom: 12px;
    background: #2a2a2a; border: 1px solid #444; color: #e0e0e0;
    border-radius: 6px; font-size: 1rem;
  }
  textarea {
    width: 100%%; height: 50vh; padding: 10px; margin-bottom: 12px;
    background: #2a2a2a; border: 1px solid #444; color: #e0e0e0;
    border-radius: 6px; font-size: 0.85rem; font-family: monospace;
    resize: vertical;
  }
  button {
    width: 100%%; padding: 14px; font-size: 1.1rem; font-weight: 600;
    background: #c0392b; color: #fff; border: none; border-radius: 6px;
    cursor: pointer;
  }
  button:active { background: #e74c3c; }
  .success { background: #1e3a1e; border: 1px solid #2d5a2d; padding: 16px; border-radius: 6px; margin: 20px 0; }
  .count { font-size: 0.8rem; color: #666; text-align: right; }
  select {
    width: 100%%; padding: 10px; margin-bottom: 12px;
    background: #2a2a2a; border: 1px solid #444; color: #e0e0e0;
    border-radius: 6px; font-size: 1rem;
  }
</style>
</head>
<body>
<h1>Transcript Receiver</h1>
<p class="info">Paste conversation text from a Claude share link. Saved as markdown to incoming folder.</p>
<form method="POST" action="/save">
  <label for="filename">Session Name (becomes filename):</label>
  <input type="text" id="filename" name="filename" placeholder="e.g. 024 AWSNBLM Maintenance" required>

  <label for="project">Project:</label>
  <select id="project" name="project">
    <option value="AWSNBLM">AWSNBLM</option>
    <option value="NLMINTA">NLMINTA</option>
    <option value="CLGYSING">CLGYSING</option>
    <option value="GOV-AIPM">GOV-AIPM</option>
    <option value="other">Other</option>
  </select>

  <label for="share_url">Share Link URL (optional):</label>
  <input type="text" id="share_url" name="share_url" placeholder="https://claude.ai/share/...">

  <label for="content">Conversation Text:</label>
  <textarea id="content" name="content" placeholder="Paste the full conversation text here..." required></textarea>

  <button type="submit">Save Transcript</button>
</form>
</body>
</html>"""

SUCCESS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Saved!</title>
<style>
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, sans-serif;
    background: #1a1a1a; color: #e0e0e0;
    padding: 16px; max-width: 800px; margin: 0 auto;
  }
  .success { background: #1e3a1e; border: 1px solid #2d5a2d; padding: 16px; border-radius: 6px; margin: 20px 0; }
  a { color: #5dade2; }
  .meta { font-size: 0.85rem; color: #888; margin-top: 8px; }
</style>
</head>
<body>
<div class="success">
  <h2>Transcript Saved</h2>
  <p class="meta">File: {filename}</p>
  <p class="meta">Size: {size}</p>
  <p class="meta">Path: {path}</p>
</div>
<p><a href="/">Save another transcript</a></p>
</body>
</html>"""


class TranscriptHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_FORM.encode())
        elif self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            files = os.listdir(SAVE_DIR)
            self.wfile.write(json.dumps({"status": "ok", "files": len(files), "save_dir": SAVE_DIR}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path != "/save":
            self.send_response(404)
            self.end_headers()
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")
        params = parse_qs(body)

        filename_raw = params.get("filename", ["untitled"])[0].strip()
        project = params.get("project", ["other"])[0].strip()
        share_url = params.get("share_url", [""])[0].strip()
        content = params.get("content", [""])[0].strip()

        if not content:
            self.send_response(400)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Error: No content provided")
            return

        # Build filename
        timestamp = datetime.now().strftime("%Y-%m-%d")
        safe_name = "".join(c if c.isalnum() or c in " -_()" else "_" for c in filename_raw)
        safe_name = safe_name.strip().replace("  ", " ").replace(" ", "-")
        filename = f"{timestamp}_{project}_{safe_name}.md"

        # Build markdown
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        md = f"# {filename_raw}\n"
        md += f"`Project: {project}`\n"
        md += f"`Saved: {now}`\n"
        if share_url:
            md += f"`Source: {share_url}`\n"
        md += f"\n---\n\n"
        md += content

        # Save
        filepath = os.path.join(SAVE_DIR, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(md)

        file_size = os.path.getsize(filepath)
        size_str = f"{file_size:,} bytes"

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        resp = SUCCESS_HTML.format(
            filename=html.escape(filename),
            size=size_str,
            path=html.escape(filepath)
        )
        self.wfile.write(resp.encode())
        print(f"[SAVED] {filename} ({size_str})")

    def log_message(self, format, *args):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {args[0]}")


if __name__ == "__main__":
    os.makedirs(SAVE_DIR, exist_ok=True)
    server = HTTPServer(("127.0.0.1", PORT), TranscriptHandler)
    print(f"Transcript Receiver running on port {PORT}")
    print(f"Saving to: {SAVE_DIR}")
    server.serve_forever()
