(async function () {
  const ext = globalThis.browser || globalThis.chrome;
  const C = globalThis.TV.constants;
  const $ = (id) => document.getElementById(id);
  const s = await ext.storage.local.get(["token", "port", "checkpointEvery", "checkpointMode", "fullMode"]);
  $("token").value = s.token || "";
  $("port").value = s.port || C.DEFAULT_PORT;
  $("every").value = s.checkpointEvery || C.DEFAULT_CHECKPOINT_EVERY;
  $("mode").value = s.checkpointMode || "remind";
  $("full").checked = s.fullMode === true;
  $("save").onclick = async () => {
    const port = Number($("port").value), every = Number($("every").value);
    if (!Number.isInteger(port) || port < 1024 || port > 65535 || !Number.isInteger(every) || every < 1) {
      $("msg").textContent = "Check the port and checkpoint values.";
      return;
    }
    await ext.storage.local.set({ token: $("token").value.trim(), port, checkpointEvery: every,
      checkpointMode: $("mode").value, fullMode: $("full").checked });
    $("msg").textContent = "Saved.";
  };
})();
