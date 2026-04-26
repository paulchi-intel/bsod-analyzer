# BSOD Analyzer — Chrome Extension

Chrome side panel that analyzes Windows kernel crash dumps (`MEMORY.DMP`) by running `kd.exe` locally via a Native Messaging host and feeding the output to GNAI.

---

## Install

### 1. Prerequisites

Install **Debugging Tools for Windows** (part of the Windows SDK):

```
C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe
```

### 2. Load the extension

1. Open `chrome://extensions/` → enable **Developer mode**.
2. **Load unpacked** → select this folder.

### 3. Register the native messaging host

The easiest way is to let the extension guide you:

1. Load the extension and open the side panel.
2. If the native host is not yet registered, a **🔧 Native Host Setup** dialog appears automatically.
3. The dialog shows the exact PowerShell command with your Extension ID already filled in:
   ```powershell
   powershell -ExecutionPolicy Bypass -File "native_host\install.ps1" -ExtensionId <YOUR_EXT_ID>
   ```
4. Click **Copy**, paste it into PowerShell (no admin needed), and press Enter.
5. Click **Retry** in the dialog — the status bar turns green when the host is found.

### 4. First-time setup

1. **🔑** → paste GNAI API Key → Confirm.
2. Select model from the dropdown (auto-populated after key is set).
3. **⚙️** → set debugger path / symbol path / proxy if needed.

---

## Usage

1. Open the side panel → click the drop zone → pick a `.dmp` from the file dialog.
2. Click a quick-analysis button — `kd.exe` runs locally, output appears inline, then GNAI explains it.
3. Ask free-text follow-ups (GNAI retains full kd context).
4. **📄 Generate Markdown Report** compiles everything into a structured report, saves it to `Documents\BSOD Reports\`, and opens the folder in Explorer.

> Chrome cannot read drag-and-drop file paths; clicking the drop zone is required.

---

## Quick-analysis buttons

Click **?** next to the section title for a full in-browser guide (繁中 / 简中 / EN).

| Button                      | kd commands                                                                             |
| --------------------------- | --------------------------------------------------------------------------------------- |
| 🧠 Full Triage + AI Summary | `vertarget; .bugcheck; !analyze -v; kb 100; lm t n; !irql; !sysinfo smbios; !cpuinfo` |
| 🔍 !analyze -v              | `.bugcheck; !analyze -v`                                                              |
| 📚 Call Stack               | `kb 100; !thread`                                                                     |
| 💻 Loaded Modules           | `lm t n`                                                                              |
| 🖥️ System / CPU / BIOS    | `vertarget; !sysinfo smbios; !cpuinfo`                                                |
| 🧮 Memory / Pool            | `!vm; !poolused 2; !memusage 0`                                                       |
| 🧵 Current Thread / IRQL    | `!thread; !irql; kv`                                                                  |
| 📄 Generate Markdown Report | GNAI-only (uses all collected kd outputs)                                               |

---

## Architecture

```
sidepanel.js  ──stdio──►  bsod_host.py  ──►  kd.exe -z <dump> -c "..."
                                                        │
                                                   textual output
                                                        │
background.js  ──HTTPS──►  gnai.intel.com  ◄───────────┘
```

- No HTTP server, no open ports. Chrome spawns the host via stdio pipes.
- Only this extension ID can invoke the host (`allowed_origins`).
- The dump file never leaves the machine; only `kd.exe` text output is sent to GNAI.
- Host truncates output at 900 KB (Chrome's 1 MB per-message cap).

---

## Native host protocol

`[u32 LE length][UTF-8 JSON]` — one request in, one response out, process exits.

| cmd             | Request                                           | Response                                                     |
| --------------- | ------------------------------------------------- | ------------------------------------------------------------ |
| `health`      | `{kd_path}`                                     | `{ok, kd_exists, kd_path, host_version}`                   |
| `browse`      | `{}`                                            | `{ok, path, name, size}` or `{ok:false, cancelled:true}` |
| `kd`          | `{dump, commands, kd_path, symbol_path, proxy}` | `{ok, returncode, output, stderr, truncated}`              |
| `save_report` | `{content, filename}`                           | `{ok, path}`                                               |

---

## Files

```
bsod-analyzer/
├── manifest.json             # MV3 (sidePanel + nativeMessaging + tabs)
├── background.js             # Service worker — GNAI chat + model list
├── sidepanel.html            # UI
├── sidepanel.js              # Native messaging + quick actions + chat
├── options.html              # Setup info page
├── guide.html                # Quick-actions guide (繁體中文)
├── guide-zh-CN.html          # Quick-actions guide (简体中文)
├── guide-en.html             # Quick-actions guide (English)
└── native_host/
    ├── bsod_host.py          # Native messaging host (Python stdlib only)
    └── install.ps1           # HKCU registry installer
```
