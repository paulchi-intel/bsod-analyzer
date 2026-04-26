#!/usr/bin/env python3
"""BSOD Analyzer — Chrome Native Messaging Host.

Runs locally, spawned on-demand by Chrome when the extension calls
`chrome.runtime.sendNativeMessage('com.bsod.copilot', ...)`.

Protocol (stdin/stdout, binary):
    [4-byte little-endian length][UTF-8 JSON body]

One message in, one message out, then exit.

Supported commands (message.cmd):
    health : verify kd.exe is reachable
    browse : show Windows file dialog, return picked .dmp path
    kd     : run `kd.exe -z <dump> -c "<cmds>; q"` with symbol path + proxy env
"""

import json
import os
import struct
import subprocess
import sys

DEFAULT_KD_PATH = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe"
DEFAULT_SYMBOL_PATH = r"srv*C:\symbols*https://msdl.microsoft.com/download/symbols"
KD_TIMEOUT_SEC = 300
BROWSE_TIMEOUT_SEC = 600
MAX_OUTPUT_CHARS = 900_000  # stay under Chrome's 1 MB per-message cap


# ---------- Native messaging I/O ----------

def read_message():
    raw_length = sys.stdin.buffer.read(4)
    if len(raw_length) < 4:
        sys.exit(0)
    length = struct.unpack('<I', raw_length)[0]
    raw = sys.stdin.buffer.read(length)
    return json.loads(raw.decode('utf-8'))


def send_message(obj):
    data = json.dumps(obj, ensure_ascii=False).encode('utf-8')
    sys.stdout.buffer.write(struct.pack('<I', len(data)))
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


# ---------- Command handlers ----------

def handle_health(msg):
    kd = msg.get('kd_path') or DEFAULT_KD_PATH
    return {
        'ok': True,
        'kd_path': kd,
        'kd_exists': os.path.isfile(kd),
        'host_version': '2.0.0',
    }


def handle_browse(_msg):
    # Use PowerShell + Windows Forms to open a native OpenFileDialog.
    script = (
        'Add-Type -AssemblyName System.Windows.Forms;'
        '$owner = New-Object System.Windows.Forms.Form;'
        '$owner.TopMost = $true;'
        '$owner.ShowInTaskbar = $false;'
        '$owner.Opacity = 0;'
        '$owner.Show();'
        '$dlg = New-Object System.Windows.Forms.OpenFileDialog;'
        '$dlg.Filter = "Dump files (*.dmp)|*.dmp|All files (*.*)|*.*";'
        '$dlg.Title = "Select MEMORY.DMP";'
        '$dlg.Multiselect = $false;'
        'if ($dlg.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) '
        '{ [Console]::Out.Write($dlg.FileName) };'
        '$owner.Dispose()'
    )
    try:
        result = subprocess.run(
            ['powershell.exe', '-NoProfile', '-STA', '-Command', script],
            capture_output=True, text=True, timeout=BROWSE_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error': 'file dialog timed out'}
    except Exception as e:
        return {'ok': False, 'error': f'failed to open file dialog: {e}'}

    path = (result.stdout or '').strip()
    if not path:
        return {'ok': False, 'cancelled': True}
    if not os.path.isfile(path):
        return {'ok': False, 'error': f'selected file not found: {path}'}
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    return {
        'ok': True,
        'path': path,
        'name': os.path.basename(path),
        'size': size,
    }


def handle_kd(msg):
    dump = msg.get('dump') or ''
    commands = msg.get('commands') or ''
    kd = msg.get('kd_path') or DEFAULT_KD_PATH
    symbol_path = msg.get('symbol_path') or DEFAULT_SYMBOL_PATH
    proxy = msg.get('proxy') or ''

    if not os.path.isfile(dump):
        return {'ok': False, 'error': f'dump not found: {dump}'}
    if not os.path.isfile(kd):
        return {'ok': False, 'error': f'kd.exe not found: {kd}'}
    if not commands:
        return {'ok': False, 'error': 'no kd commands provided'}

    env = os.environ.copy()
    env['_NT_SYMBOL_PATH'] = symbol_path
    if proxy:
        env['HTTP_PROXY'] = proxy
        env['HTTPS_PROXY'] = proxy

    full_cmd = commands.rstrip().rstrip(';') + '; q'

    try:
        result = subprocess.run(
            [kd, '-z', dump, '-c', full_cmd],
            capture_output=True, text=True,
            timeout=KD_TIMEOUT_SEC, env=env,
            errors='replace',
        )
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error': f'kd.exe timed out after {KD_TIMEOUT_SEC}s'}
    except Exception as e:
        return {'ok': False, 'error': f'kd.exe failed: {e}'}

    output = result.stdout or ''
    truncated = False
    if len(output) > MAX_OUTPUT_CHARS:
        output = output[:MAX_OUTPUT_CHARS] + '\n\n[...output truncated by native host at 900KB...]\n'
        truncated = True
    stderr = (result.stderr or '')[:4000]

    return {
        'ok': True,
        'returncode': result.returncode,
        'output': output,
        'stderr': stderr,
        'truncated': truncated,
    }


def handle_find_dump(msg):
    """Locate a dump file by name + size.

    Step 1: Instant Python search of well-known directories.
    Step 2: PowerShell Get-ChildItem scan of all fixed drives (depth 4, ~5-15 s).
    Returns {ok, path, name, size} on success or {ok: False, error} when not found.
    """
    name = (msg.get('name') or '').strip()
    size = int(msg.get('size') or 0)
    if not name:
        return {'ok': False, 'error': 'no filename provided'}

    def size_ok(actual):
        if size == 0:
            return True
        return abs(actual - size) <= max(size * 0.01, 4096)

    def try_path(p):
        if os.path.isfile(p):
            try:
                actual = os.path.getsize(p)
                if size_ok(actual):
                    return {'ok': True, 'path': p, 'name': os.path.basename(p), 'size': actual}
            except OSError:
                pass
        return None

    userprofile = os.environ.get('USERPROFILE', '')
    windir = os.environ.get('SystemRoot', os.environ.get('WINDIR', r'C:\Windows'))

    # --- Step 1: Instant fixed-path search ---
    quick_dirs = [
        os.path.join(windir, 'Minidump'),
        windir,
        os.path.join(userprofile, 'Desktop'),
        os.path.join(userprofile, 'Downloads'),
        os.path.join(userprofile, 'Documents'),
        os.path.join(userprofile, 'AppData', 'Local', 'Temp'),
        os.path.join(userprofile, 'AppData', 'Local', 'CrashDumps'),
        os.environ.get('TEMP', ''),
    ]
    for d in quick_dirs:
        if d:
            hit = try_path(os.path.join(d, name))
            if hit:
                return hit

    # --- Step 2: PowerShell scan across all fixed drives ---
    # Escape single quotes in name to prevent injection
    safe_name = name.replace("'", "''")
    script = (
        f"$n='{safe_name}'; $sz={size}; "
        "$tol=[Math]::Max($sz*0.01,4096); "
        "Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | "
        "ForEach-Object { "
        "  try { "
        "    Get-ChildItem -Path $_.Root -Filter $n -Recurse -Depth 4 "
        "      -ErrorAction SilentlyContinue -Force | "
        "    Where-Object { $sz -eq 0 -or [Math]::Abs($_.Length-$sz) -le $tol } | "
        "    Select-Object -First 1 -ExpandProperty FullName "
        "  } catch {} "
        "} | Select-Object -First 1"
    )
    try:
        result = subprocess.run(
            ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
            capture_output=True, text=True, timeout=20,
        )
        found = (result.stdout or '').strip().splitlines()
        found = [l.strip() for l in found if l.strip()]
        if found:
            p = found[0]
            if os.path.isfile(p):
                try:
                    actual = os.path.getsize(p)
                except OSError:
                    actual = size
                return {'ok': True, 'path': p, 'name': os.path.basename(p), 'size': actual}
    except Exception:
        pass

    return {'ok': False, 'error': f'"{name}" not found on this machine; please use the file browser'}


def handle_stat_dump(msg):
    """Validate a user-supplied absolute path and return metadata.

    Used by the manual path text input in the UI.
    """
    path = (msg.get('path') or '').strip().strip('"').strip("'")
    if not path:
        return {'ok': False, 'error': 'no path provided'}
    if not os.path.isfile(path):
        return {'ok': False, 'error': f'File not found: {path}'}
    try:
        size = os.path.getsize(path)
    except OSError as e:
        return {'ok': False, 'error': f'Cannot read file: {e}'}
    return {'ok': True, 'path': path, 'name': os.path.basename(path), 'size': size}


def handle_save_report(msg):
    """Write a Markdown report to disk and open its folder in Explorer.

    Request: {content: str, filename: str}
    Response: {ok, path}
    """
    content  = msg.get('content') or ''
    filename = (msg.get('filename') or 'bsod_report').strip()
    # Sanitise filename — keep alphanum, dash, underscore, dot
    safe = ''.join(c if c.isalnum() or c in '-_.' else '_' for c in filename)
    if not safe.lower().endswith('.md'):
        safe += '.md'

    out_dir = os.path.join(os.path.expanduser('~'), 'Documents', 'BSOD Reports')
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, safe)

    try:
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(content)
    except OSError as e:
        return {'ok': False, 'error': f'Failed to write report: {e}'}

    # Open Explorer and highlight the file
    try:
        subprocess.Popen(['explorer.exe', '/select,', out_path])
    except Exception:
        pass  # non-fatal — file was already written

    return {'ok': True, 'path': out_path}


HANDLERS = {
    'health':      handle_health,
    'browse':      handle_browse,
    'find_dump':   handle_find_dump,
    'stat_dump':   handle_stat_dump,
    'kd':          handle_kd,
    'save_report': handle_save_report,
}


def main():
    try:
        msg = read_message()
    except Exception as e:
        send_message({'ok': False, 'error': f'read error: {e}'})
        return

    cmd = (msg.get('cmd') or '').lower()
    handler = HANDLERS.get(cmd)
    if handler is None:
        send_message({'ok': False, 'error': f'unknown cmd: {cmd!r}'})
        return

    try:
        resp = handler(msg)
    except Exception as e:
        resp = {'ok': False, 'error': f'handler {cmd} failed: {e}'}
    send_message(resp)


if __name__ == '__main__':
    main()
