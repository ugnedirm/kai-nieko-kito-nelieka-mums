(async function () {
  const ext = globalThis.browser || globalThis.chrome;
  const C = globalThis.TV.constants;
  const $ = (id) => document.getElementById(id);
  const s = await ext.storage.local.get(["token", "port", "checkpointEvery", "checkpointMode", "fullMode", "captureFiles", "attachMode"]);
  $("token").value = s.token || "";
  $("port").value = s.port || C.DEFAULT_PORT;
  $("every").value = s.checkpointEvery || C.DEFAULT_CHECKPOINT_EVERY;
  $("mode").value = s.checkpointMode || "remind";
  $("full").checked = s.fullMode === true;
  $("files").checked = s.captureFiles !== false;
  $("attach").value = ["ask", "auto", "off"].includes(s.attachMode) ? s.attachMode : "ask";
  const send = (type) => ext.runtime.sendMessage({ type });
  async function refresh() {
    await send("pair_check");
    const v = await send("vault_status");
    $("conn").className = v.connected ? "ok" : "warn";
    $("conn").textContent = v.connected ? "Connected to your vault." :
      v.running ? "Your vault is running but this browser is not connected yet." :
        "Your vault is not running. See \"How does this work?\" for how to start it.";
    $("connect").disabled = !v.running || v.connected;
  }
  $("connect").onclick = async () => { await send("pair_start"); };
  refresh();
  setInterval(refresh, 2500);
  $("save").onclick = async () => {
    const port = Number($("port").value), every = Number($("every").value);
    if (!Number.isInteger(port) || port < 1024 || port > 65535 || !Number.isInteger(every) || every < 1) {
      $("msg").textContent = "Check the port and checkpoint values.";
      return;
    }
    const typed = $("token").value.trim();
    await ext.storage.local.set({ ...(typed ? { token: typed } : {}), port, checkpointEvery: every,
      checkpointMode: $("mode").value, fullMode: $("full").checked, captureFiles: $("files").checked, attachMode: $("attach").value });
    $("msg").textContent = "Saved.";
  };
})();
