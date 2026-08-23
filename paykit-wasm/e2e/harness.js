// Browser-side harness for the paykit-wasm e2e.
//
// Loads the actual wasm-pack artifact from /pkg/ and exposes the module plus
// a mutable state bag on `window`. All orchestration happens from the
// Playwright driver via page.evaluate; wasm handles (sessions, handshakes,
// links) never leave the page, so they live in `window.state`.

import init, * as paykit from "/pkg/paykit_wasm.js";

window.state = {};

window.paykitReady = (async () => {
  await init();
  window.paykit = paykit;
  document.getElementById("status").textContent = "paykit-wasm ready";
  return true;
})();

// Extract the 32-byte link id from EncryptedLinkHandle.snapshot() bytes.
//
// Wire format (paykit-lib snapshot.rs + pubky-noise serializer.rs):
// the snapshot is JSON (`SnapshotWire`) whose `state` field is the fixed
// binary layout of PubkyNoiseSessionState, where byte [108] is has_link_id
// and bytes [109..141] are the link id.
window.linkIdFromSnapshot = (snapshotBytes) => {
  const wire = JSON.parse(new TextDecoder().decode(snapshotBytes));
  const state = wire.state;
  if (!Array.isArray(state) || state.length < 141) {
    throw new Error(`unexpected snapshot state layout (len ${state?.length})`);
  }
  if (state[108] !== 1) {
    throw new Error("snapshot has no link id (has_link_id flag is 0)");
  }
  return state
    .slice(109, 141)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
};

window.sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
