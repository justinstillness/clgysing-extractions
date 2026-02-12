# Chronicler Fix Log

## 2026-02-12 — flush_pipeline Tool Discovery Fix (Session 026)

**Problem:** `Chronicler:flush_pipeline` was registered on the server but
invisible to Claude's MCP tool discovery. All other 9 Chronicler tools
worked normally. Persisted across multiple sessions.

**Root Cause:** In `chronicler.py`, the `flush_pipeline` function was
defined AFTER the `if __name__ == "__main__": mcp.run()` entry point
block. FastMCP collects `@mcp.tool()` registrations when building the
tool manifest at server start. Since `mcp.run()` blocks, any tool
definitions below it were not included in the manifest sent to clients
during the MCP connection handshake.

**Fix:** Moved the `import asyncio` statement and entire `flush_pipeline`
function definition (with its `@mcp.tool()` decorator) to BEFORE the
entry point block. Backup created as `chronicler.py.bak.flush_move`.

**Verification:**
- `grep -n` confirms flush_pipeline (line 545) before Entry point (line 605)
- `systemctl restart chronicler` — clean restart, no errors
- `server_status` responds normally
- MCP discovery test: requires fresh Claude session (manifest cached per session)

**Files Modified:**
- `/home/ubuntu/chronicler/chronicler.py` (live on EC2)
- Backup: `/home/ubuntu/chronicler/chronicler.py.bak.flush_move`
