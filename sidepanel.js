// sidepanel.js - BSOD Analyzer
// Windows kernel crash-dump analyzer.
//
// No HTTP backend — kd.exe is invoked via a Chrome Native Messaging host
// (`com.bsod.copilot`, installed via native_host/install.ps1).
//
// Header controls:
//   🔑 apiKeyBtn    - opens GNAI API key modal  (bsodGnaiToken)
//   modelSelect     - GNAI model dropdown       (bsodModel)
//   languageSelect  - 繁/简/EN dropdown          (bsodLanguage)
//   ⚙️ settingsBtn  - tool path / symbol path / proxy

const NATIVE_HOST = 'com.bsod.copilot';

// ========== Translations ==========
const TRANSLATIONS = {
  'en': {
    'clear': 'Clear',
    'send': 'Send',
    'status-ready': 'Ready',
    'status-browsing': 'Opening file browser...',
    'status-running-kd': 'Running kd.exe...',
    'status-analyzing': 'Asking GNAI...',
    'status-loading-models': 'Loading models...',
    'status-error': 'Error',
    'status-done': 'Done',
    'empty-title': 'BSOD Analyzer',
    'empty-text': 'Pick a MEMORY.DMP above, then click a quick-analysis button.',
    'input-placeholder': 'Ask about the crash... (e.g. explain the call stack)',
    'pick-dump': 'Pick MEMORY.DMP',
    'pick-dump-hint': 'Click to open the Windows file browser and select a .dmp',
    'host-checking': 'Checking native host...',
    'host-connected': '✅ Native host OK (kd.exe found)',
    'host-no-kd': '⚠️ Native host OK, but kd.exe not found at configured path',
    'host-missing': '❌ Native host not installed — run native_host\\install.ps1 -ExtensionId <id>',
    'quick-actions-title': 'Quick Analysis',
    'qa-triage': '🧠 Full Triage + AI Summary',
    'qa-bugcheck': '🔍 !analyze -v',
    'qa-stack': '📚 Call Stack (kb 100)',
    'qa-modules': '💻 Loaded Modules (lm t n)',
    'qa-sysinfo': '🖥️ System / CPU / BIOS',
    'qa-memory': '🧮 Memory / Pool (!vm, !poolused)',
    'qa-thread': '🧵 Current Thread / IRQL',
    'qa-report': '📄 Generate Markdown Report',
    'settings-tools': 'Debugger Tools',
    'settings-tool-path': 'Debugger tool path',
    'settings-tool-path-hint': 'Path to kd.exe. windbg.exe lives in the same folder; kd.exe is what the native host invokes.',
    'settings-symbol-path': 'Symbol path (_NT_SYMBOL_PATH)',
    'settings-proxy': 'Proxy (for symbol server, optional)',
    'settings-save': 'Save',
    'settings-saved': '✓ Saved',
    'apikey-modal-title': 'Set GNAI API Key',
    'apikey-modal-hint': 'Please enter your GNAI API Key.',
    'apikey-cancel': 'Cancel',
    'apikey-confirm': 'Confirm',
    'apikey-updated': 'API key updated',
    'apikey-required': 'Please set your GNAI key first (click the title)',
    'system-dump-picked': 'Dump selected',
    'error-no-dump': 'Please pick a .dmp file first',
    'error-no-gnai': 'GNAI_TOKEN not set. Click the title bar to configure.',
    'error-host': 'Native host not reachable. Run native_host\\install.ps1 -ExtensionId <id>.',
    'error-empty': 'Please enter a question',
    'pick-cancelled': 'File selection cancelled',
    'qa-triage-tip': 'Run 8 diagnostic commands at once; AI summarizes root cause and suggests next steps.',
    'qa-bugcheck-tip': 'Identify the faulting module and its origin.',
    'qa-stack-tip': 'View call stack and thread; annotate crash point and third-party driver frames.',
    'qa-modules-tip': 'List all loaded modules; flag third-party, outdated, and high-risk drivers.',
    'qa-sysinfo-tip': 'Capture hardware snapshot; flag old BIOS and unusual configurations.',
    'qa-memory-tip': 'Analyze memory usage; flag leaks and exhaustion symptoms.',
    'qa-thread-tip': 'View thread state and IRQL; determine execution context at crash time.',
    'qa-report-tip': 'Compile this session into a Markdown report with summary, root cause, system info, faulting component, call stack, evidence, and recommendations.',
    'saved-prompts': 'Saved Prompts',
    'saved-prompts-title': 'Saved Prompts Manager',
    'manage-prompts': 'Manage',
    'add-prompt': 'Add Prompt',
    'empty-prompts': 'No saved prompts yet. Add one below.',
    'empty-saved-prompts': 'Click "Manage" to add saved prompts',
    'new-prompt-placeholder': 'Enter a new prompt...'
  },
  'zh-TW': {
    'clear': '清除',
    'send': '發送',
    'status-ready': '準備就緒',
    'status-browsing': '開啟檔案瀏覽器中...',
    'status-running-kd': '執行 kd.exe 中...',
    'status-analyzing': '詢問 GNAI 中...',
    'status-loading-models': '載入模型中...',
    'status-error': '發生錯誤',
    'status-done': '完成',
    'empty-title': 'BSOD Analyzer',
    'empty-text': '選取 MEMORY.DMP 後，點選快速分析按鈕。',
    'input-placeholder': '詢問關於此次當機... (例如：解釋 call stack)',
    'pick-dump': '選取 MEMORY.DMP',
    'pick-dump-hint': '點擊以開啟 Windows 檔案瀏覽器並選擇 .dmp',
    'host-checking': '檢查 native host 中...',
    'host-connected': '✅ Native host 正常（已找到 kd.exe）',
    'host-no-kd': '⚠️ Native host 正常，但找不到 kd.exe',
    'host-missing': '❌ Native host 未安裝 — 請執行 native_host\\install.ps1 -ExtensionId <id>',
    'quick-actions-title': '快速分析',
    'qa-triage': '🧠 完整 Triage + AI 摘要',
    'qa-bugcheck': '🔍 !analyze -v',
    'qa-stack': '📚 Call Stack (kb 100)',
    'qa-modules': '💻 載入模組 (lm t n)',
    'qa-sysinfo': '🖥️ 系統 / CPU / BIOS',
    'qa-memory': '🧮 記憶體 / Pool (!vm, !poolused)',
    'qa-thread': '🧵 目前 Thread / IRQL',
    'qa-report': '📄 產生 Markdown 報告',
    'settings-tools': '偵錯工具',
    'settings-tool-path': '偵錯工具路徑',
    'settings-tool-path-hint': 'kd.exe 路徑。windbg.exe 與 kd.exe 位於同一資料夾，native host 使用 kd.exe 進行分析。',
    'settings-symbol-path': '符號路徑 (_NT_SYMBOL_PATH)',
    'settings-proxy': 'Proxy（符號伺服器用，選填）',
    'settings-save': '儲存',
    'settings-saved': '✓ 已儲存',
    'apikey-modal-title': '設定 GNAI API Key',
    'apikey-modal-hint': '請輸入 GNAI API Key。',
    'apikey-cancel': '取消',
    'apikey-confirm': '確認',
    'apikey-updated': 'API key 已更新',
    'apikey-required': '請先設定 GNAI key（點擊標題）',
    'system-dump-picked': '已選取 dump',
    'error-no-dump': '請先選取 .dmp 檔案',
    'error-no-gnai': '尚未設定 GNAI_TOKEN。請點擊標題列設定。',
    'error-host': '無法連線 native host。請執行 native_host\\install.ps1 -ExtensionId <id>。',
    'error-empty': '請輸入問題',
    'pick-cancelled': '已取消選取檔案',
    'qa-triage-tip': '一鍵執行8條診斷指令，AI自動分析故障原因並提供調查建議。',
    'qa-bugcheck-tip': '判斷肇事模組來源。',
    'qa-stack-tip': '查看Stack和Thread，標注崩潰點和第三方驅動位置。',
    'qa-modules-tip': '列出所有載入模組，標記第三方驅動、過時驅動和高風險模組。',
    'qa-sysinfo-tip': '蒐集硬體快照，標記過舊 BIOS 和異常配置。',
    'qa-memory-tip': '分析記憶體使用，標記洩漏和耗盡徵兆。',
    'qa-thread-tip': '查看Thread狀態和中斷等級，判斷崩潰發生時的執行上下文。',
    'qa-report-tip': '把本session整理成 Markdown 分析報告，包含摘要、根因、系統資訊、肇事元件、堆疊、證據和建議。',
    'saved-prompts': '常用提示詞',
    'saved-prompts-title': '常用提示詞管理',
    'manage-prompts': '管理',
    'add-prompt': '新增提示詞',
    'empty-prompts': '還沒有常用提示詞，請在下方新增',
    'empty-saved-prompts': '點擊「管理」來新增常用提示詞',
    'new-prompt-placeholder': '輸入新的常用提示詞...'
  },
  'zh-CN': {
    'clear': '清除',
    'send': '发送',
    'status-ready': '准备就绪',
    'status-browsing': '打开文件浏览器中...',
    'status-running-kd': '执行 kd.exe 中...',
    'status-analyzing': '询问 GNAI 中...',
    'status-loading-models': '载入模型中...',
    'status-error': '发生错误',
    'status-done': '完成',
    'empty-title': 'BSOD Analyzer',
    'empty-text': '选取 MEMORY.DMP 后，点击快速分析按钮。',
    'input-placeholder': '询问关于此次崩溃... (例如：解释 call stack)',
    'pick-dump': '选取 MEMORY.DMP',
    'pick-dump-hint': '点击以打开 Windows 文件浏览器并选择 .dmp',
    'host-checking': '检查 native host 中...',
    'host-connected': '✅ Native host 正常（已找到 kd.exe）',
    'host-no-kd': '⚠️ Native host 正常，但找不到 kd.exe',
    'host-missing': '❌ Native host 未安装 — 请执行 native_host\\install.ps1 -ExtensionId <id>',
    'quick-actions-title': '快速分析',
    'qa-triage': '🧠 完整 Triage + AI 摘要',
    'qa-bugcheck': '🔍 !analyze -v',
    'qa-stack': '📚 Call Stack (kb 100)',
    'qa-modules': '💻 加载模块 (lm t n)',
    'qa-sysinfo': '🖥️ 系统 / CPU / BIOS',
    'qa-memory': '🧮 内存 / Pool (!vm, !poolused)',
    'qa-thread': '🧵 当前 Thread / IRQL',
    'qa-report': '📄 生成 Markdown 报告',
    'settings-tools': '调试工具',
    'settings-tool-path': '调试工具路径',
    'settings-tool-path-hint': 'kd.exe 路径。windbg.exe 与 kd.exe 位于同一文件夹，native host 使用 kd.exe 进行分析。',
    'settings-symbol-path': '符号路径 (_NT_SYMBOL_PATH)',
    'settings-proxy': 'Proxy（符号服务器用，选填）',
    'settings-save': '保存',
    'settings-saved': '✓ 已保存',
    'apikey-modal-title': '设置 GNAI API Key',
    'apikey-modal-hint': '请输入 GNAI API Key。',
    'apikey-cancel': '取消',
    'apikey-confirm': '确认',
    'apikey-updated': 'API key 已更新',
    'apikey-required': '请先设置 GNAI key（点击标题）',
    'system-dump-picked': '已选取 dump',
    'error-no-dump': '请先选取 .dmp 文件',
    'error-no-gnai': '尚未设置 GNAI_TOKEN。请点击标题栏设置。',
    'error-host': '无法连接 native host。请执行 native_host\\install.ps1 -ExtensionId <id>。',
    'error-empty': '请输入问题',
    'pick-cancelled': '已取消选取文件',
    'qa-triage-tip': '一键执行8条诊断指令，AI自动分析故障原因并提供调查建议。',
    'qa-bugcheck-tip': '判断肇事模块来源。',
    'qa-stack-tip': '查看Stack和Thread，标注崩溃点和第三方驱动位置。',
    'qa-modules-tip': '列出所有载入模块，标记第三方驱动、过时驱动和高风险模块。',
    'qa-sysinfo-tip': '收集硬件快照，标记过旧 BIOS 和异常配置。',
    'qa-memory-tip': '分析内存使用，标记泄漏和耗尽征兆。',
    'qa-thread-tip': '查看Thread状态和中断等级，判断崩溃发生时的执行上下文。',
    'qa-report-tip': '把本session整理成 Markdown 分析报告，包含摘要、根因、系统资讯、肇事元件、堆栈、证据和建议。',
    'saved-prompts': '常用提示词',
    'saved-prompts-title': '常用提示词管理',
    'manage-prompts': '管理',
    'add-prompt': '新增提示词',
    'empty-prompts': '还没有常用提示词，请在下方新增',
    'empty-saved-prompts': '点击「管理」来新增常用提示词',
    'new-prompt-placeholder': '输入新的常用提示词...'
  }
};

// ========== Constants ==========
const DEFAULT_KD_PATH = 'C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\kd.exe';
const DEFAULT_SYMBOL_PATH = 'srv*C:\\symbols*https://msdl.microsoft.com/download/symbols';
const DEFAULT_MODEL = 'gpt-4o';
const FALLBACK_OPENAI_MODELS    = ['gpt-4o', 'gpt-4.1', 'gpt-5-mini', 'gpt-5-nano', 'o3-mini'];
const FALLBACK_ANTHROPIC_MODELS = ['claude-4-6-opus', 'claude-4-6-sonnet', 'claude-4-5-opus', 'claude-4-5-sonnet', 'claude-4-5-haiku'];

// ========== State ==========
let currentLanguage = 'en';
let currentModel = DEFAULT_MODEL;
let gnaiToken = '';
let availableOpenaiModels    = FALLBACK_OPENAI_MODELS.slice();
let availableAnthropicModels = FALLBACK_ANTHROPIC_MODELS.slice();

let dumpPath = null;       // full Windows path returned by native host
let dumpMeta = null;       // {name, size}
let kdOutputs = [];
let messages = [];
let chatLog = [];     // visual chat log for session restore
let savedPrompts = [];

// ========== Native messaging ==========
function nativeCall(payload) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendNativeMessage(NATIVE_HOST, payload, (resp) => {
        if (chrome.runtime.lastError) {
          resolve({ ok: false, error: chrome.runtime.lastError.message || 'native host error', _hostMissing: true });
          return;
        }
        resolve(resp || { ok: false, error: 'empty response from native host' });
      });
    } catch (e) {
      resolve({ ok: false, error: e.message || String(e), _hostMissing: true });
    }
  });
}

// ========== Settings storage ==========
async function loadSettings() {
  return chrome.storage.local.get({
    bsodGnaiToken: '',
    bsodModel: DEFAULT_MODEL,
    bsodKdPath: DEFAULT_KD_PATH,
    bsodSymbolPath: DEFAULT_SYMBOL_PATH,
    bsodProxy: '',
    bsodLanguage: 'en',
    bsodSavedPrompts: []
  });
}

async function saveSettings() {
  const data = {
    bsodKdPath: document.getElementById('settingsToolPath').value.trim() || DEFAULT_KD_PATH,
    bsodSymbolPath: document.getElementById('settingsSymbolPath').value.trim() || DEFAULT_SYMBOL_PATH,
    bsodProxy: document.getElementById('settingsProxy').value.trim()
  };
  await chrome.storage.local.set(data);
  const msg = document.getElementById('settingsSavedMsg');
  msg.classList.add('show');
  setTimeout(() => msg.classList.remove('show'), 2000);
  await checkHost();
}

async function populateSettingsUI() {
  const s = await loadSettings();
  document.getElementById('settingsToolPath').value = s.bsodKdPath || DEFAULT_KD_PATH;
  document.getElementById('settingsSymbolPath').value = s.bsodSymbolPath || DEFAULT_SYMBOL_PATH;
  document.getElementById('settingsProxy').value = s.bsodProxy || '';
}

function toggleSettingsPanel() {
  document.getElementById('settingsPanel').classList.toggle('show');
}

// ========== i18n ==========
function t(key) {
  return TRANSLATIONS[currentLanguage]?.[key] || TRANSLATIONS['en']?.[key] || key;
}

function updateUILanguage() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    const text = t(key);
    if (key === 'apikey-modal-hint') el.innerHTML = text;
    else el.textContent = text;
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    el.placeholder = t(el.getAttribute('data-i18n-placeholder'));
  });
  document.getElementById('languageSelect').value = currentLanguage;
  if (document.querySelector('.quick-actions')) showQuickActions();
}

function updateStatus(type, text) {
  document.getElementById('statusDot').className = `status-indicator ${type}`;
  document.getElementById('statusText').textContent = text || '';
}

// ========== API Key modal ==========
function openApiKeyModal() {
  const modal = document.getElementById('apiKeyModal');
  const input = document.getElementById('apiKeyInput');
  input.value = gnaiToken || '';
  modal.classList.add('show');
  setTimeout(() => input.focus(), 50);
}

function closeApiKeyModal() {
  document.getElementById('apiKeyModal').classList.remove('show');
}

async function confirmApiKey() {
  const val = document.getElementById('apiKeyInput').value.trim();
  if (!val) { closeApiKeyModal(); return; }
  gnaiToken = val;
  await chrome.storage.local.set({ bsodGnaiToken: val });
  closeApiKeyModal();
  updateStatus('ready', t('apikey-updated'));
  await loadModels();
}

// ========== Model dropdown ==========
async function loadModels() {
  if (!gnaiToken) {
    availableOpenaiModels    = FALLBACK_OPENAI_MODELS.slice();
    availableAnthropicModels = FALLBACK_ANTHROPIC_MODELS.slice();
    populateModelSelect();
    return;
  }
  updateStatus('loading', t('status-loading-models'));
  try {
    const resp = await new Promise((resolve) => {
      chrome.runtime.sendMessage(
        { type: 'GET_MODELS', gnaiToken },
        (r) => resolve(r || { ok: false, error: 'no response' })
      );
    });
    if (resp.ok) {
      availableOpenaiModels = Array.isArray(resp.openaiModels) && resp.openaiModels.length
        ? resp.openaiModels : FALLBACK_OPENAI_MODELS.slice();
      availableAnthropicModels = Array.isArray(resp.anthropicModels) && resp.anthropicModels.length
        ? resp.anthropicModels : FALLBACK_ANTHROPIC_MODELS.slice();
    } else {
      availableOpenaiModels    = FALLBACK_OPENAI_MODELS.slice();
      availableAnthropicModels = FALLBACK_ANTHROPIC_MODELS.slice();
    }
  } catch (_e) {
    availableOpenaiModels    = FALLBACK_OPENAI_MODELS.slice();
    availableAnthropicModels = FALLBACK_ANTHROPIC_MODELS.slice();
  }
  populateModelSelect();
  updateStatus('ready', t('status-ready'));
}

function populateModelSelect() {
  const sel = document.getElementById('modelSelect');
  sel.innerHTML = '';

  const appendGroup = (models, label) => {
    if (!models || !models.length) return;
    const header = document.createElement('option');
    header.value = '';
    header.disabled = true;
    header.textContent = `--- ${label} ---`;
    sel.appendChild(header);
    models.forEach(m => {
      const opt = document.createElement('option');
      opt.value = m;
      opt.textContent = m;
      sel.appendChild(opt);
    });
  };

  appendGroup(availableOpenaiModels,    'OpenAI');
  appendGroup(availableAnthropicModels, 'Anthropic');

  const all = [...availableOpenaiModels, ...availableAnthropicModels];
  if (!all.includes(currentModel)) {
    currentModel = all[0] || DEFAULT_MODEL;
  }
  sel.value = currentModel;
}

// ========== Install helper modal ==========
function openInstallModal() {
  const modal = document.getElementById('installModal');
  const extId = chrome.runtime.id;
  const nativeHostDir = chrome.runtime.getURL('native_host/').replace(/\//g, '\\').replace(/^chrome-extension:\\\\[^\\]+\\/, '');
  const cmd = `powershell -ExecutionPolicy Bypass -File "native_host\\install.ps1" -ExtensionId ${extId}`;
  document.getElementById('installCmdText').textContent = cmd;
  modal.classList.add('show');
}

function closeInstallModal() {
  document.getElementById('installModal').classList.remove('show');
}

async function checkHost() {
  const bar = document.getElementById('backendBar');
  const dot = document.getElementById('backendDot');
  const textEl = document.getElementById('backendText');
  textEl.textContent = t('host-checking');
  bar.classList.remove('connected', 'disconnected');
  dot.className = 'status-indicator loading';

  const s = await loadSettings();
  const resp = await nativeCall({ cmd: 'health', kd_path: s.bsodKdPath });
  if (!resp.ok) {
    bar.classList.add('disconnected');
    dot.className = 'status-indicator error';
    textEl.textContent = t('host-missing');
    openInstallModal();
    return false;
  }
  if (!resp.kd_exists) {
    bar.classList.add('disconnected');
    dot.className = 'status-indicator error';
    textEl.textContent = `${t('host-no-kd')} — ${resp.kd_path}`;
    return false;
  }
  bar.classList.add('connected');
  dot.className = 'status-indicator';
  textEl.textContent = t('host-connected');
  return true;
}

// ========== Apply dump path to UI ==========
async function applyDump({ path, name, size }) {
  dumpPath = path;
  dumpMeta = { name, size };
  document.getElementById('dumpDropZone').classList.add('has-file');
  document.getElementById('dumpDropIcon').textContent = '✅';
  document.getElementById('dumpFileName').textContent = path;
  document.getElementById('dumpFileName').style.display = 'block';

  kdOutputs = [];
  messages = [];
  chatLog = [];
  clearMessagesUI();
  addSystemMessage(`${t('system-dump-picked')}: ${path}`);
  showQuickActions();
  updateStatus('ready', t('status-ready'));
  saveSession();
}

// ========== Pick dump via native file dialog ==========
let _pickingDump = false;
async function pickDump() {
  if (_pickingDump) return;
  _pickingDump = true;
  updateStatus('loading', t('status-browsing'));
  const resp = await nativeCall({ cmd: 'browse' });
  _pickingDump = false;
  if (!resp.ok) {
    if (resp.cancelled) {
      updateStatus('ready', t('pick-cancelled'));
      return;
    }
    updateStatus('error', resp.error || t('error-host'));
    return;
  }
  await applyDump({ path: resp.path, name: resp.name, size: resp.size });
}

// ========== Handle a File object from input or DnD ==========
// Chrome cannot expose OS path from File objects — open native dialog directly.
async function handleDumpFile(_file) {
  await pickDump();
}

function clearDump() {
  dumpPath = null;
  dumpMeta = null;
  kdOutputs = [];
  messages = [];
  chatLog = [];
  document.getElementById('dumpDropZone').classList.remove('has-file');
  document.getElementById('dumpDropIcon').textContent = '💥';
  document.getElementById('dumpFileName').style.display = 'none';
  document.getElementById('dumpFileName').textContent = '';
  clearMessagesUI();
  chrome.storage.local.remove('bsodSession');
}

// ========== Run kd via native host ==========
async function runKd(commands, label) {
  if (!dumpPath) throw new Error(t('error-no-dump'));
  const s = await loadSettings();
  const resp = await nativeCall({
    cmd: 'kd',
    dump: dumpPath,
    commands,
    kd_path: s.bsodKdPath,
    symbol_path: s.bsodSymbolPath,
    proxy: s.bsodProxy,
    label: label || ''
  });
  if (!resp.ok) throw new Error(resp.error || 'kd failed');
  return resp;
}

// ========== GNAI chat ==========
async function chatViaGnai(msgs) {
  if (!gnaiToken) return { ok: false, error: t('error-no-gnai') };
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(
      { type: 'CHAT', messages: msgs, language: currentLanguage, gnaiToken, model: currentModel },
      (response) => {
        if (chrome.runtime.lastError) {
          resolve({ ok: false, error: chrome.runtime.lastError.message });
          return;
        }
        resolve(response || { ok: false, error: 'No response from background' });
      }
    );
  });
}

// ========== UI helpers ==========
function clearMessagesUI() {
  const container = document.getElementById('messagesContainer');
  // Detach drop zone before clearing, then reinsert at top
  const zone = document.getElementById('dumpDropZone');
  container.innerHTML = `
    <div class="empty-state">
      <div class="empty-state-icon">🔑</div>
      <div class="empty-state-title">${t('empty-title')}</div>
      <div class="empty-state-text">${t('empty-text')}</div>
    </div>
  `;
  if (zone) container.insertBefore(zone, container.firstChild);
}

function removeEmptyState() {
  const es = document.querySelector('.empty-state');
  if (es) es.remove();
}

function addSystemMessage(text, skipLog = false) {
  removeEmptyState();
  const container = document.getElementById('messagesContainer');
  const div = document.createElement('div');
  div.className = 'message system';
  div.textContent = text;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
  if (!skipLog) chatLog.push({ type: 'system', text });
}

function addUserMessage(text, skipLog = false) {
  removeEmptyState();
  const container = document.getElementById('messagesContainer');
  const div = document.createElement('div');
  div.className = 'message user';
  div.textContent = text;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
  if (!skipLog) chatLog.push({ type: 'user', text });
}

function addKdMessage(label, output, skipLog = false) {
  removeEmptyState();
  const container = document.getElementById('messagesContainer');
  const div = document.createElement('div');
  div.className = 'message kd';
  const head = label ? `── ${label} ──\n` : '';
  div.textContent = head + (output || '(no output)');
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
  if (!skipLog) chatLog.push({ type: 'kd', label, text: output });
}

function renderMarkdown(md) {
  let html = md;
  html = html.replace(/```(\w*)\n([\s\S]*?)```/g, (_m, _lang, code) => {
    const escaped = code.replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return `<pre><code>${escaped}</code></pre>`;
  });
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
  html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>');
  html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
  html = html.replace(/^- (.+)$/gm, '<li>$1</li>');
  html = html.replace(/(<li>.*?<\/li>\n?)+/gs, (m) => `<ul>${m}</ul>`);
  // Tables: match consecutive | lines with a separator row
  html = html.replace(/((?:^\|[^\n]*(?:\n|$))+)/gm, (block) => {
    const lines = block.trim().split('\n').filter(l => l.trim().startsWith('|'));
    if (lines.length < 3) return block;
    const isSep = (l) => /^\|[\s\-:|]+\|/.test(l.trim());
    if (!isSep(lines[1])) return block;
    const cells = (l) => l.trim().replace(/^\||\|$/g, '').split('|').map(c => c.trim());
    const headers = cells(lines[0]);
    const rows = lines.slice(2).filter(l => l.trim()).map(cells);
    let t = '<div class="table-wrapper"><table><thead><tr>';
    headers.forEach(h => { t += `<th>${h}</th>`; });
    t += '</tr></thead><tbody>';
    rows.forEach(r => { t += '<tr>'; r.forEach(c => { t += `<td>${c}</td>`; }); t += '</tr>'; });
    t += '</tbody></table></div>';
    return t;
  });
  html = html.replace(/\n\n/g, '</p><p>');
  html = html.replace(/\n/g, '<br>');
  html = '<p>' + html + '</p>';
  html = html.replace(/<p><\/p>/g, '');
  html = html.replace(/<p>(<h[23]>)/g, '$1').replace(/(<\/h[23]>)<\/p>/g, '$1');
  html = html.replace(/<p>(<ul>)/g, '$1').replace(/(<\/ul>)<\/p>/g, '$1');
  html = html.replace(/<p>(<pre>)/g, '$1').replace(/(<\/pre>)<\/p>/g, '$1');
  html = html.replace(/<p>(<div class="table-wrapper">)/g, '$1').replace(/(<\/div>)<\/p>/g, '$1');
  return html;
}

function addAssistantMessage(md, skipLog = false) {
  removeEmptyState();
  const container = document.getElementById('messagesContainer');
  const div = document.createElement('div');
  div.className = 'message assistant';
  div.innerHTML = renderMarkdown(md);
  container.appendChild(div);
  div.scrollIntoView({ behavior: 'smooth', block: 'start' });
  if (!skipLog) chatLog.push({ type: 'assistant', text: md });
}

// ========== Dump zone ==========
function setupDropZone() {
  const zone = document.getElementById('dumpDropZone');
  const input = document.getElementById('dumpFileInput');
  const removeBtn = document.getElementById('dumpRemoveBtn');

  // Click zone → native file dialog
  zone.addEventListener('click', (e) => {
    if (e.target === removeBtn || e.target.closest('.file-drop-zone-remove')) return;
    pickDump();
  });

  input.addEventListener('change', async () => {
    input.value = '';
    await pickDump();
  });

  removeBtn.addEventListener('click', (e) => { e.stopPropagation(); clearDump(); });

  // Drag events
  zone.addEventListener('dragenter', (e) => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragover',  (e) => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', (e) => { e.preventDefault(); zone.classList.remove('drag-over'); });
  zone.addEventListener('drop', async (e) => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    await pickDump();
  });
}

// ========== Saved Prompts ==========
function showSavedPromptsSection() {
  const container = document.getElementById('messagesContainer');
  const existing = container.querySelector('.saved-prompts-section');
  if (existing) existing.remove();

  const savedNode = document.createElement('div');
  savedNode.className = 'saved-prompts-section';

  const listHtml = !savedPrompts.length
    ? `<div class="empty-saved-prompts">${t('empty-saved-prompts')}</div>`
    : savedPrompts.map((prompt, index) =>
        `<button class="saved-prompt-btn" data-index="${index}">${prompt.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</button>`
      ).join('');

  savedNode.innerHTML = `
    <div class="saved-prompts-header">
      <div class="saved-prompts-title">${t('saved-prompts')}</div>
      <button class="manage-prompts-btn" id="managePromptsBtn">${t('manage-prompts')}</button>
    </div>
    <div class="saved-prompts-list">${listHtml}</div>
  `;

  const quickNode = container.querySelector('.quick-actions');
  if (quickNode) {
    quickNode.insertAdjacentElement('afterend', savedNode);
  } else {
    const firstMsg = container.querySelector('.message');
    if (firstMsg) container.insertBefore(savedNode, firstMsg); else container.appendChild(savedNode);
  }

  savedNode.querySelector('#managePromptsBtn').addEventListener('click', openSavedPromptsModal);
  savedNode.querySelectorAll('.saved-prompt-btn').forEach(btn => {
    btn.addEventListener('click', () => usePrompt(Number(btn.dataset.index)));
  });
}

function openSavedPromptsModal() {
  document.getElementById('savedPromptsModal').classList.add('show');
  renderSavedPromptsList();
}

function closeSavedPromptsModal() {
  document.getElementById('savedPromptsModal').classList.remove('show');
  document.getElementById('newPromptInput').value = '';
}

function renderSavedPromptsList() {
  const list = document.getElementById('savedPromptsList');
  if (!savedPrompts.length) {
    list.innerHTML = `
      <div class="empty-prompts">
        <div class="empty-prompts-icon">📝</div>
        <div class="empty-prompts-text">${t('empty-prompts')}</div>
      </div>`;
    return;
  }
  list.innerHTML = savedPrompts.map((prompt, index) => `
    <div class="saved-prompt-item">
      <div class="saved-prompt-text" data-index="${index}">${prompt.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</div>
      <div class="saved-prompt-actions">
        <button class="prompt-action-btn delete-prompt-btn" data-index="${index}" title="Delete">🗑️</button>
      </div>
    </div>`).join('');

  list.querySelectorAll('.saved-prompt-text').forEach(el => {
    el.addEventListener('click', () => usePrompt(Number(el.dataset.index)));
  });
  list.querySelectorAll('.delete-prompt-btn').forEach(btn => {
    btn.addEventListener('click', () => deletePrompt(Number(btn.dataset.index)));
  });
}

async function addNewPrompt() {
  const input = document.getElementById('newPromptInput');
  const text = input.value.trim();
  if (!text) return;
  savedPrompts.push(text);
  await chrome.storage.local.set({ bsodSavedPrompts: savedPrompts });
  input.value = '';
  renderSavedPromptsList();
  if (dumpPath) showSavedPromptsSection();
}

async function deletePrompt(index) {
  savedPrompts.splice(index, 1);
  await chrome.storage.local.set({ bsodSavedPrompts: savedPrompts });
  renderSavedPromptsList();
  if (dumpPath) showSavedPromptsSection();
}

function usePrompt(index) {
  const prompt = savedPrompts[index];
  if (!prompt) return;
  const input = document.getElementById('messageInput');
  input.value = prompt;
  input.style.height = 'auto';
  input.style.height = Math.min(input.scrollHeight, 120) + 'px';
  input.focus();
  closeSavedPromptsModal();
}

// ========== Quick Actions ==========
const QUICK_ACTIONS = [
  { key: 'qa-triage',   tooltipKey: 'qa-triage-tip',   commands: '.echo === vertarget ===; vertarget; .echo === bugcheck ===; .bugcheck; .echo === !analyze -v ===; !analyze -v; .echo === kb 100 ===; kb 100; .echo === lm t n ===; lm t n; .echo === !irql ===; !irql; .echo === !sysinfo smbios ===; !sysinfo smbios; .echo === !cpuinfo ===; !cpuinfo', label: 'Full Triage', aiPrompt: 'Below is the full triage output. Provide: (1) Bugcheck code & name, (2) Root-cause one-liner, (3) Faulting module & driver type, (4) Key evidence from !analyze -v, (5) 3-5 targeted follow-up kd commands. Be specific; quote exact addresses/modules.' },
  { key: 'qa-bugcheck', tooltipKey: 'qa-bugcheck-tip', commands: '.echo === .bugcheck ===; .bugcheck; .echo === !analyze -v ===; !analyze -v', label: '!analyze -v', aiPrompt: 'Interpret this !analyze -v output. Identify the bugcheck code/args, explain the failure mechanism, point out the faulting frame, and flag whether the faulting module is inbox, third-party, or a known problem driver.' },
  { key: 'qa-stack',    tooltipKey: 'qa-stack-tip',    commands: '.echo === kb 100 ===; kb 100; .echo === !thread ===; !thread', label: 'Call Stack', aiPrompt: 'Annotate this call stack frame-by-frame in plain English. Identify the crash point, the transition from usermode/kernel if any, and highlight any third-party driver frames.' },
  { key: 'qa-modules',  tooltipKey: 'qa-modules-tip',  commands: '.echo === lm t n ===; lm t n', label: 'Loaded Modules', aiPrompt: 'From this loaded-modules list, flag: (1) third-party drivers, (2) unsigned or outdated drivers if detectable by date, (3) well-known problem drivers (AV, VPN, RGB, overclocking, DMA-heavy Thunderbolt/USB). Suggest which to investigate with lmvm.' },
  { key: 'qa-sysinfo',  tooltipKey: 'qa-sysinfo-tip',  commands: '.echo === vertarget ===; vertarget; .echo === !sysinfo smbios ===; !sysinfo smbios; .echo === !cpuinfo ===; !cpuinfo', label: 'System Info', aiPrompt: 'Summarize the system: OS build, manufacturer, model, BIOS version/date, CPU family/model/stepping, microcode. Flag anything unusual (very old BIOS, pre-release Windows, unusual CPU stepping).' },
  { key: 'qa-memory',   tooltipKey: 'qa-memory-tip',   commands: '.echo === !vm ===; !vm; .echo === !poolused 2 ===; !poolused 2; .echo === !memusage ===; !memusage 0', label: 'Memory / Pool', aiPrompt: 'Analyze memory and pool usage. Flag pool tag leaks, low VA signs, and excessive paged/nonpaged pool. Recommend which tag to investigate further.' },
  { key: 'qa-thread',   tooltipKey: 'qa-thread-tip',   commands: '.echo === !thread ===; !thread; .echo === !irql ===; !irql; .echo === kv ===; kv', label: 'Thread / IRQL', aiPrompt: 'From the current thread, IRQL and verbose stack (kv), identify: current IRQL, whether we are at DPC/ISR/passive, any trap/exception frames to expand with .trap or .cxr, and what the thread was doing when it died.' },
  { key: 'qa-report',   tooltipKey: 'qa-report-tip',   commands: null, label: 'Markdown Report', aiPrompt: null }
];

function showQuickActions() {
  const container = document.getElementById('messagesContainer');
  const existing = container.querySelector('.quick-actions');
  if (existing) existing.remove();

  const div = document.createElement('div');
  div.className = 'quick-actions';
  const titleDiv = document.createElement('div');
  titleDiv.className = 'quick-actions-title';
  titleDiv.appendChild(document.createTextNode(t('quick-actions-title')));
  const helpBtn = document.createElement('button');
  helpBtn.className = 'qa-help-btn';
  helpBtn.textContent = '?';
  const helpTipMap = { 'zh-TW': '詳細說明', 'zh-CN': '详细说明', 'en': 'Button Guide' };
  helpBtn.title = helpTipMap[currentLanguage] || '詳細說明';
  const guideFileMap = { 'zh-TW': 'guide.html', 'zh-CN': 'guide-zh-CN.html', 'en': 'guide-en.html' };
  const guideFile = guideFileMap[currentLanguage] || 'guide.html';
  helpBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    chrome.tabs.create({ url: chrome.runtime.getURL(guideFile) });
  });
  titleDiv.appendChild(helpBtn);
  div.appendChild(titleDiv);
  const grid = document.createElement('div');
  grid.className = 'quick-actions-grid';
  QUICK_ACTIONS.forEach(qa => {
    const btn = document.createElement('button');
    btn.className = 'quick-action-btn';
    btn.dataset.key = qa.key;
    btn.textContent = t(qa.key);
    if (qa.tooltipKey) btn.dataset.tooltip = t(qa.tooltipKey);
    btn.addEventListener('click', () => runQuickAction(qa));
    grid.appendChild(btn);
  });
  div.appendChild(grid);

  const firstMsg = container.querySelector('.message');
  if (firstMsg) container.insertBefore(div, firstMsg); else container.appendChild(div);

  showSavedPromptsSection();
}

function setButtonsDisabled(disabled) {
  document.querySelectorAll('.quick-action-btn').forEach(b => b.disabled = disabled);
  document.getElementById('sendBtn').disabled = disabled;
  document.getElementById('messageInput').disabled = disabled;
}

async function runQuickAction(qa) {
  if (!dumpPath) { updateStatus('error', t('error-no-dump')); return; }
  setButtonsDisabled(true);
  try {
    if (qa.key === 'qa-report') {
      await generateReport();
      return;
    }
    updateStatus('loading', t('status-running-kd'));
    addSystemMessage(`▶ kd: ${qa.label}`);
    const res = await runKd(qa.commands, qa.label);
    const output = res.output || '';
    addKdMessage(qa.label, output);
    kdOutputs.push({ label: qa.label, commands: qa.commands, output });

    if (qa.aiPrompt) {
      if (!gnaiToken) {
        addSystemMessage(t('error-no-gnai'));
        updateStatus('error', t('apikey-required'));
        return;
      }
      updateStatus('loading', t('status-analyzing'));
      const userContent = `kd.exe output for step "${qa.label}":\n\n\`\`\`\n${truncate(output, 40000)}\n\`\`\`\n\nTask: ${qa.aiPrompt}`;
      const resp = await chatViaGnai([...messages, { role: 'user', content: userContent }]);
      if (resp.ok) {
        addAssistantMessage(resp.result);
        messages.push({ role: 'user', content: userContent });
        messages.push({ role: 'assistant', content: resp.result });
      } else {
        addSystemMessage(`GNAI error: ${resp.error}`);
      }
    }
    updateStatus('ready', t('status-done'));
  } catch (err) {
    updateStatus('error', err.message);
    addSystemMessage(`Error: ${err.message}`);
  } finally {
    setButtonsDisabled(false);
    saveSession();
  }
}

async function generateReport() {
  if (kdOutputs.length === 0) {
    addSystemMessage('Run at least one quick-analysis step first (e.g. Full Triage) before generating a report.');
    updateStatus('ready', t('status-ready'));
    return;
  }
  if (!gnaiToken) {
    addSystemMessage(t('error-no-gnai'));
    updateStatus('error', t('apikey-required'));
    return;
  }
  addUserMessage(t('qa-report'));
  updateStatus('loading', t('status-analyzing'));
  const combined = kdOutputs.map(k => `--- ${k.label} ---\n${truncate(k.output, 8000)}`).join('\n\n');
  const prompt = `Using the kd.exe outputs below, produce a structured Markdown BSOD analysis report with these sections:

## Bugcheck Summary (table: Code, Name, Description, Arg1-4, Failure Bucket)
## Root Cause (One-Line)
## System Information (Manufacturer/Model/BIOS/CPU/OS as tables)
## Faulting Component (Module, Symbol, Driver Type)
## Call Stack (Annotated)
## Evidence (quote specific kd output snippets)
## Recommendations (specific: driver version, KB, BIOS URL, registry, config)
## Confidence & Residual Uncertainty

Fill with "N/A" if data not present. Do NOT fabricate values.

Raw kd outputs:
\`\`\`
${truncate(combined, 60000)}
\`\`\``;
  const resp = await chatViaGnai([...messages, { role: 'user', content: prompt }]);
  if (resp.ok) {
    addAssistantMessage(resp.result);
    messages.push({ role: 'user', content: prompt });
    messages.push({ role: 'assistant', content: resp.result });
    updateStatus('ready', t('status-done'));
    // Save to .md and open the folder in Explorer
    const dumpBase = dumpMeta ? dumpMeta.name.replace(/\.dmp$/i, '') : 'MEMORY';
    const ts = new Date().toISOString().slice(0, 19).replace(/[T:]/g, '_').replace(/-/g, '');
    const filename = `${dumpBase}_${ts}.md`;
    const saveResp = await nativeCall({ cmd: 'save_report', content: resp.result, filename });
    if (saveResp.ok) {
      addSystemMessage(`📁 報告已儲存: ${saveResp.path}`);
    } else {
      addSystemMessage(`⚠️ 報告儲存失敗: ${saveResp.error}`);
    }
  } else {
    addSystemMessage(`GNAI error: ${resp.error}`);
    updateStatus('error', t('status-error'));
  }
}

function truncate(s, max) {
  if (!s) return '';
  return s.length > max ? s.slice(0, max) + '\n\n[... truncated ...]' : s;
}

// ========== Free-form chat ==========
async function sendMessage() {
  const input = document.getElementById('messageInput');
  const userMessage = input.value.trim();
  if (!userMessage) { updateStatus('error', t('error-empty')); return; }
  if (!gnaiToken) {
    updateStatus('error', t('apikey-required'));
    openApiKeyModal();
    return;
  }

  setButtonsDisabled(true);
  try {
    addUserMessage(userMessage);
    input.value = '';
    input.style.height = 'auto';

    const ctx = kdOutputs.length > 0
      ? `The following kd.exe outputs have already been collected from MEMORY.DMP:\n\n${kdOutputs.map(k => `--- ${k.label} ---\n${truncate(k.output, 6000)}`).join('\n\n')}\n\n---\n\n`
      : '';
    const dumpCtx = dumpMeta ? `Dump: ${dumpMeta.name} (${(dumpMeta.size/1024/1024).toFixed(1)} MB)\n\n` : '';
    const content = `${dumpCtx}${ctx}User question: ${userMessage}

If answering requires additional kd.exe commands, list the exact commands in a fenced code block labelled "kd-commands" and explain why. The user can then run them via quick-action buttons.`;

    updateStatus('loading', t('status-analyzing'));
    const resp = await chatViaGnai([...messages, { role: 'user', content }]);
    if (resp.ok) {
      addAssistantMessage(resp.result);
      messages.push({ role: 'user', content });
      messages.push({ role: 'assistant', content: resp.result });
      updateStatus('ready', t('status-done'));
    } else {
      addSystemMessage(`GNAI error: ${resp.error}`);
      updateStatus('error', t('status-error'));
    }
  } catch (err) {
    updateStatus('error', err.message);
  } finally {
    setButtonsDisabled(false);
    input.focus();
    saveSession();
  }
}

// ========== Clear ==========
function clearChat() {
  messages = [];
  kdOutputs = [];
  chatLog = [];
  clearMessagesUI();
  if (dumpPath) showQuickActions();
  updateStatus('ready', t('status-ready'));
  saveSession();
}

// ========== Session persistence ==========
async function saveSession() {
  try {
    await chrome.storage.local.set({
      bsodSession: {
        dumpPath,
        dumpMeta,
        kdOutputs: kdOutputs.map(k => ({ label: k.label, commands: k.commands, output: truncate(k.output, 20000) })),
        messages: messages.slice(-40),
        chatLog: chatLog.slice(-100)
      }
    });
  } catch (_e) { /* storage quota exceeded — silent fail */ }
}

async function restoreSession() {
  const result = await chrome.storage.local.get('bsodSession');
  const s = result.bsodSession;
  if (!s || !s.dumpPath) return false;

  // Show loading overlay
  const container = document.getElementById('messagesContainer');
  const restoringLabel = currentLanguage === 'zh-CN' ? '正在恢复会话...' : currentLanguage === 'zh-TW' ? '正在還原 session...' : 'Restoring session...';
  const overlay = document.createElement('div');
  overlay.id = 'restoreOverlay';
  overlay.className = 'restore-overlay';
  overlay.innerHTML = `<div class="restore-spinner"></div><div class="restore-label">${restoringLabel}</div>`;
  container.appendChild(overlay);
  updateStatus('loading', restoringLabel);

  // Yield to let the browser paint the overlay before the heavy DOM work
  await new Promise(r => requestAnimationFrame(r));

  dumpPath = s.dumpPath;
  dumpMeta = s.dumpMeta || null;
  kdOutputs = Array.isArray(s.kdOutputs) ? s.kdOutputs : [];
  messages = Array.isArray(s.messages) ? s.messages : [];
  chatLog = Array.isArray(s.chatLog) ? s.chatLog : [];

  document.getElementById('dumpDropZone').classList.add('has-file');
  document.getElementById('dumpDropIcon').textContent = '✅';
  document.getElementById('dumpFileName').textContent = dumpPath;
  document.getElementById('dumpFileName').style.display = 'block';

  showQuickActions();

  for (const entry of chatLog) {
    if (entry.type === 'system')    addSystemMessage(entry.text, true);
    else if (entry.type === 'user') addUserMessage(entry.text, true);
    else if (entry.type === 'kd')   addKdMessage(entry.label, entry.text, true);
    else if (entry.type === 'assistant') addAssistantMessage(entry.text, true);
  }

  overlay.remove();
  return true;
}

// ========== Init ==========
document.addEventListener('DOMContentLoaded', async () => {
  const s = await loadSettings();
  currentLanguage = s.bsodLanguage || 'en';
  currentModel = s.bsodModel || DEFAULT_MODEL;
  gnaiToken = s.bsodGnaiToken || '';
  savedPrompts = Array.isArray(s.bsodSavedPrompts) ? s.bsodSavedPrompts : [];

  updateUILanguage();
  populateModelSelect();

  // Language dropdown
  const langSelect = document.getElementById('languageSelect');
  langSelect.value = currentLanguage;
  langSelect.addEventListener('change', async () => {
    currentLanguage = langSelect.value;
    await chrome.storage.local.set({ bsodLanguage: currentLanguage });
    updateUILanguage();
    if (dumpPath) { showQuickActions(); }
    updateStatus('ready', t('status-ready'));
  });

  // Model dropdown
  const modelSelect = document.getElementById('modelSelect');
  modelSelect.addEventListener('change', async () => {
    currentModel = modelSelect.value;
    await chrome.storage.local.set({ bsodModel: currentModel });
  });

  // API key modal (opened by clicking the header title, like key-chatter)
  document.getElementById('headerTitle').addEventListener('click', openApiKeyModal);
  document.getElementById('closeApiKeyModal').addEventListener('click', closeApiKeyModal);
  document.getElementById('apiKeyCancelBtn').addEventListener('click', closeApiKeyModal);
  document.getElementById('apiKeyConfirmBtn').addEventListener('click', confirmApiKey);
  document.getElementById('apiKeyModal').addEventListener('click', (e) => {
    if (e.target.id === 'apiKeyModal') closeApiKeyModal();
  });
  document.getElementById('apiKeyInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') confirmApiKey();
    else if (e.key === 'Escape') closeApiKeyModal();
  });

  // Core buttons
  document.getElementById('clearBtn').addEventListener('click', clearChat);
  document.getElementById('sendBtn').addEventListener('click', sendMessage);
  document.getElementById('messageInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  });
  document.getElementById('messageInput').addEventListener('input', (e) => {
    e.target.style.height = 'auto';
    e.target.style.height = Math.min(e.target.scrollHeight, 120) + 'px';
  });

  // Settings panel
  document.getElementById('settingsBtn').addEventListener('click', async () => {
    await populateSettingsUI();
    toggleSettingsPanel();
  });
  document.getElementById('settingsSaveBtn').addEventListener('click', saveSettings);

  // Install helper modal
  document.getElementById('closeInstallModal').addEventListener('click', closeInstallModal);
  document.getElementById('installModal').addEventListener('click', (e) => {
    if (e.target.id === 'installModal') closeInstallModal();
  });
  document.getElementById('installCopyBtn').addEventListener('click', () => {
    const cmd = document.getElementById('installCmdText').textContent;
    navigator.clipboard.writeText(cmd).then(() => {
      const btn = document.getElementById('installCopyBtn');
      btn.textContent = 'Copied!';
      setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
    });
  });
  document.getElementById('installRetryBtn').addEventListener('click', async () => {
    closeInstallModal();
    await checkHost();
  });

  // Saved prompts modal
  document.getElementById('closeSavedPromptsModal').addEventListener('click', closeSavedPromptsModal);
  document.getElementById('savedPromptsModal').addEventListener('click', (e) => {
    if (e.target.id === 'savedPromptsModal') closeSavedPromptsModal();
  });
  document.getElementById('addPromptBtn').addEventListener('click', addNewPrompt);
  document.getElementById('newPromptInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); addNewPrompt(); }
  });

  // Dump zone
  setupDropZone();
  await restoreSession();

  updateStatus('ready', t('status-ready'));

  // Check native host + load models
  await checkHost();
  await loadModels();

  // Prompt for API key on first run if missing
  if (!gnaiToken) openApiKeyModal();
});
