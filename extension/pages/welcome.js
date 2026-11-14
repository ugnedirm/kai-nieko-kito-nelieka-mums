(async function () {
  const ext = globalThis.browser || globalThis.chrome;
  const $ = (id) => document.getElementById(id);
  const send = (type) => ext.runtime.sendMessage({ type });

  function show(node, ok, text) {
    node.className = ok ? "ok" : "warn";
    node.textContent = text;
  }

  async function refresh() {
    await send("pair_check");
    const v = await send("vault_status");
    show($("running"), v.running, v.running ? "Your vault is running." :
      "Your vault is not running yet. Do step 1, then wait a few seconds.");
    show($("connected"), v.connected, v.connected ? "Connected. You are ready: go to step 3." :
      "Not connected yet.");
    $("connect").disabled = !v.running || v.connected;
  }

  $("connect").onclick = async () => {
    const r = await send("pair_start");
    if (!r || !r.ok) show($("connected"), false, (r && r.error) || "Could not reach your vault.");
    else show($("connected"), false, "Click Allow on the page that just opened, then come back here.");
  };

  await refresh();
  setInterval(refresh, 2500);
})();
