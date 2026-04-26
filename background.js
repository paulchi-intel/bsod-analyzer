// background.js (service worker, MV3)
// BSOD Analyzer - GNAI-powered Windows kernel crash dump analyzer

const GNAI_OPENAI_BASE_URL    = "https://gnai.intel.com/api/providers/openai/v1";
const GNAI_ANTHROPIC_BASE_URL = "https://gnai.intel.com/api/providers/anthropic";
const GNAI_DEFAULT_MODEL = "gpt-4o";
const REQUEST_TIMEOUT_MS = 180000; // 3 min for long kd outputs
const NATIVE_HOST = "com.bsod.copilot";

const FALLBACK_OPENAI_MODELS    = ["gpt-4o", "gpt-4.1", "gpt-5-mini", "gpt-5-nano", "o3-mini"];
const FALLBACK_ANTHROPIC_MODELS = ["claude-4-6-opus", "claude-4-6-sonnet", "claude-4-5-opus", "claude-4-5-sonnet", "claude-4-5-haiku"];

function isAnthropicModel(model) {
  return typeof model === "string" && model.toLowerCase().startsWith("claude");
}

chrome.action.onClicked.addListener((tab) => {
  chrome.sidePanel.open({ windowId: tab.windowId });
});

// Warm up the native messaging host as soon as the extension appears
// (install, browser start, or service-worker wake). This triggers Chrome to
// spawn bsod_host.py once so any registration/launch issues surface early,
// before the user opens the side panel.
function warmUpNativeHost(context) {
  try {
    chrome.runtime.sendNativeMessage(NATIVE_HOST, { cmd: "health" }, (resp) => {
      const err = chrome.runtime.lastError;
      if (err) {
        console.warn(`[bsod] native host warm-up failed (${context}):`, err.message);
      } else if (resp && resp.ok) {
        console.log(`[bsod] native host ready (${context}): kd=${resp.kd_exists ? "found" : "missing"} @ ${resp.kd_path}`);
      } else {
        console.warn(`[bsod] native host responded with error (${context}):`, resp);
      }
    });
  } catch (e) {
    console.warn(`[bsod] sendNativeMessage threw (${context}):`, e);
  }
}

chrome.runtime.onInstalled.addListener(() => warmUpNativeHost("onInstalled"));
chrome.runtime.onStartup.addListener(() => warmUpNativeHost("onStartup"));
// Also warm up on service-worker boot (covers reloads & the first action click).
warmUpNativeHost("sw-boot");

const SYSTEM_PROMPTS = {
  'en': `You are an expert Windows kernel debugging engineer. You analyze raw output from kd.exe (WinDbg) against Windows kernel crash dumps (MEMORY.DMP / BSOD).

Your expertise:
- Bugcheck codes (0x7E, 0x133, 0x124, 0x1A, 0x9F, 0xEF, 0x101, 0x10D, 0x139, 0x1CA, 0x20001, 0xA, 0xD1, 0x50, 0x7A, 0x7F, 0x3B, 0x1E, 0xE2, 0xC2, 0x19, etc.)
- Call stack interpretation, trap frames, context records (.trap, .cxr)
- Faulting module identification, driver age/signing, third-party driver flags
- Pool / PTE / VA analysis (!pool, !pte, !vm, !poolused)
- DPC watchdog, IPI, CLOCK_WATCHDOG, MCE / WHEA (hardware-reported)
- DMA / IOMMU faults (!DMAR, !pcicfglog)
- Power / Pnp / WDF (!poaction, !wdfkd.wdflogdump)

Rules:
1. Quote the exact kd output when citing evidence.
2. Keep WinDbg commands, module names, and register values in English/verbatim.
3. If the evidence is inconclusive, say so — never fabricate values.
4. Recommend a short list of next kd commands when a deep-dive is warranted.
5. Output structured Markdown with headings.`,

  'zh-TW': `你是一位專業的 Windows 核心除錯工程師。你會分析 kd.exe (WinDbg) 針對 Windows 核心當機 dump (MEMORY.DMP / BSOD) 所產生的原始輸出。

你的專業領域：
- Bugcheck codes（0x7E、0x133、0x124、0x1A、0x9F、0xEF、0x101、0x10D、0x139、0x1CA、0x20001、0xA、0xD1、0x50、0x7A、0x7F、0x3B、0x1E、0xE2、0xC2、0x19 等）
- Call stack、trap frame、context record 解讀 (.trap, .cxr)
- 故障模組識別、driver 版本/簽章、第三方 driver 風險提示
- Pool / PTE / VA 分析 (!pool, !pte, !vm, !poolused)
- DPC watchdog、IPI、CLOCK_WATCHDOG、MCE / WHEA（硬體層級錯誤）
- DMA / IOMMU faults (!DMAR, !pcicfglog)
- Power / Pnp / WDF (!poaction, !wdfkd.wdflogdump)

規則：
1. 引用證據時，請原文引用 kd 的輸出。
2. WinDbg 指令、模組名稱、暫存器值請保留英文/原文。
3. 若證據不足以下結論，直接說明，不要捏造數值。
4. 值得深入追查時，建議接下來要執行的 kd 指令清單（精簡 3–5 條）。
5. 使用繁體中文撰寫，輸出結構化 Markdown。`,

  'zh-CN': `你是一位专业的 Windows 内核调试工程师。你会分析 kd.exe (WinDbg) 针对 Windows 内核崩溃 dump (MEMORY.DMP / BSOD) 产生的原始输出。

你的专业领域：
- Bugcheck codes（0x7E、0x133、0x124、0x1A、0x9F、0xEF、0x101、0x10D、0x139、0x1CA、0x20001、0xA、0xD1、0x50、0x7A、0x7F、0x3B、0x1E、0xE2、0xC2、0x19 等）
- Call stack、trap frame、context record 解读 (.trap, .cxr)
- 故障模块识别、driver 版本/签名、第三方 driver 风险提示
- Pool / PTE / VA 分析 (!pool, !pte, !vm, !poolused)
- DPC watchdog、IPI、CLOCK_WATCHDOG、MCE / WHEA（硬件层错误）
- DMA / IOMMU faults (!DMAR, !pcicfglog)
- Power / Pnp / WDF (!poaction, !wdfkd.wdflogdump)

规则：
1. 引用证据时请原文引用 kd 的输出。
2. WinDbg 指令、模块名称、寄存器值请保留英文/原文。
3. 若证据不足以下结论，直接说明，不要捏造数值。
4. 值得深入追查时，建议接下来要执行的 kd 指令清单（精简 3–5 条）。
5. 使用简体中文撰写，输出结构化 Markdown。`
};

async function callGnai(messages, language, gnaiToken, model) {
  const systemPrompt = SYSTEM_PROMPTS[language] || SYSTEM_PROMPTS['en'];
  const selectedModel = model || GNAI_DEFAULT_MODEL;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    if (isAnthropicModel(selectedModel)) {
      // Anthropic messages API: system is a top-level field; response lives at content[0].text
      const body = {
        model: selectedModel,
        system: systemPrompt,
        messages,
        max_tokens: 6000
      };
      const response = await fetch(`${GNAI_ANTHROPIC_BASE_URL}/v1/messages`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${gnaiToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(body),
        signal: controller.signal
      });
      if (!response.ok) {
        const text = await response.text().catch(() => "");
        throw new Error(`GNAI API error (${response.status}): ${text.slice(0, 500)}`);
      }
      const data = await response.json();
      return data?.content?.[0]?.text || "(No response content)";
    }

    // OpenAI chat completions API
    const fullMessages = [{ role: "system", content: systemPrompt }, ...messages];
    const isReasoningModel = /^o\d/i.test(selectedModel) || /^gpt-5/i.test(selectedModel);
    const body = {
      model: selectedModel,
      messages: fullMessages,
      stream: false,
      ...(isReasoningModel
        ? { max_completion_tokens: 6000 }
        : { temperature: 0.2, max_tokens: 6000 })
    };
    const response = await fetch(`${GNAI_OPENAI_BASE_URL}/chat/completions`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${gnaiToken}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(body),
      signal: controller.signal
    });
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new Error(`GNAI API error (${response.status}): ${text.slice(0, 500)}`);
    }
    const data = await response.json();
    return data?.choices?.[0]?.message?.content || "(No response content)";
  } catch (err) {
    if (err && err.name === "AbortError") {
      throw new Error(`GNAI request timed out after ${REQUEST_TIMEOUT_MS / 1000}s`);
    }
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function fetchGnaiModels(gnaiToken) {
  const fetchList = async (url, fallback) => {
    const ctrl = new AbortController();
    const to = setTimeout(() => ctrl.abort(), 10000);
    try {
      const r = await fetch(url, {
        headers: { "Authorization": `Bearer ${gnaiToken}` },
        signal: ctrl.signal
      });
      if (!r.ok) return fallback.slice();
      const d = await r.json();
      const list = (d.data || []).map(m => String(m?.id || "").trim()).filter(Boolean);
      return list.length ? list : fallback.slice();
    } catch (_e) {
      return fallback.slice();
    } finally {
      clearTimeout(to);
    }
  };

  const [openaiModels, anthropicModels] = await Promise.all([
    fetchList(`${GNAI_OPENAI_BASE_URL}/models`,       FALLBACK_OPENAI_MODELS),
    fetchList(`${GNAI_ANTHROPIC_BASE_URL}/v1/models`, FALLBACK_ANTHROPIC_MODELS)
  ]);

  return { openaiModels, anthropicModels };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "CHAT") {
    (async () => {
      try {
        const { messages, language, gnaiToken, model } = message;
        if (!gnaiToken) {
          sendResponse({ ok: false, error: "GNAI_TOKEN not set. Click 🔑 in the header to configure." });
          return;
        }
        const result = await callGnai(messages, language || 'en', gnaiToken, model);
        sendResponse({ ok: true, result });
      } catch (err) {
        console.error("CHAT error:", err);
        sendResponse({ ok: false, error: err.message || String(err) });
      }
    })();
    return true;
  }

  if (message.type === "GET_MODELS") {
    (async () => {
      const noKeyDefault = {
        ok: true,
        openaiModels: FALLBACK_OPENAI_MODELS.slice(),
        anthropicModels: FALLBACK_ANTHROPIC_MODELS.slice(),
        models: [...FALLBACK_OPENAI_MODELS, ...FALLBACK_ANTHROPIC_MODELS]
      };
      try {
        const { gnaiToken } = message;
        if (!gnaiToken) { sendResponse(noKeyDefault); return; }
        const { openaiModels, anthropicModels } = await fetchGnaiModels(gnaiToken);
        sendResponse({
          ok: true,
          openaiModels, anthropicModels,
          models: [...openaiModels, ...anthropicModels]
        });
      } catch (err) {
        console.warn("GET_MODELS fallback:", err?.message);
        sendResponse(noKeyDefault);
      }
    })();
    return true;
  }
});
