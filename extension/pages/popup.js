(async function () {
  const ext = globalThis.browser || globalThis.chrome;
  const state = document.getElementById("state"), list = document.getElementById("checks");
  async function tabMessage(type) {
    const [tab] = await ext.tabs.query({ active: true, currentWindow: true });
    if (!tab) throw new Error("no tab");
    return ext.tabs.sendMessage(tab.id, { type });
  }
  async function selftest() {
    list.replaceChildren();
    try {
      const r = await tabMessage("selftest");
      state.textContent = r.ok ? `${r.site} adapter v${r.version}: OK` : `${r.site} adapter v${r.version}: BROKEN, capture disabled`;
      for (const c of r.checks) {
        const li = document.createElement("li");
        li.textContent = `${c.ok ? "ok" : c.required ? "FAIL" : "missing"}: ${c.name}`;
        list.append(li);
      }
    } catch (_) {
      state.textContent = "Open a ChatGPT or Claude chat first.";
    }
  }
  document.getElementById("test").onclick = selftest;
  document.getElementById("save").onclick = async () => {
    try { const r = await tabMessage("start_handover"); state.textContent = r.ok ? "Request placed in the chat box. Press send." : r.error; }
    catch (_) { state.textContent = "Open a ChatGPT or Claude chat first."; }
  };
  document.getElementById("options").onclick = () => ext.runtime.openOptionsPage();
  selftest();
})();
