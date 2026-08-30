// Browser e2e for paykit-wasm homeserver-backed Encrypted Link flows.
//
// Drives the actual wasm-pack artifact (../pkg) in real Chromium contexts
// against a live Pubky testnet homeserver. Two isolated browser contexts
// (Alice = initiator, Bob = responder) prove:
//
//   1. dev-keypair signup sessions from a browser,
//   1b. session survival across a page reload via exportSession (secret-free
//       metadata) + the browser's HTTP-only cookie + restoreSession, and a
//       clean rejection for malformed restore input,
//   1c. cookie-ONLY resume: the exported metadata is DISCARDED across a
//       second reload and resumeSessionFromCookie rebuilds the session from
//       the browser cookie alone (plus exportSession round-trip on the
//       resumed handle and a typed rejection for a cookieless pubky),
//   2. receiver marker publish + discovery (both directions),
//   3. the Noise XX handshake driven over homeserver outbox slots,
//   4. Private Application Message exchange both directions with
//      marketplace-shaped kinds and payload integrity,
//   5. marker removal,
//   6. link snapshot -> context destroyed -> restoreEncryptedLink in a fresh
//      context -> still receives new messages (multi-device/refresh survival).
//
// Environment: a Pubky testnet (homeserver + pkarr relay). Defaults target
// the payments-env docker stack's host port mappings. `PubkyClient.testnet()`
// hardcodes the fixed testnet localhost ports (pkarr relay 15411; the
// homeserver pkarr record advertises HTTP_PORT 6286), so this script bridges
// those exact host ports to the mapped docker ports. See docs/browser-e2e.md.
//
// Usage: npm install && node run.mjs   (from this directory)

import { createServer, Socket } from "node:net";
import http from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import assert from "node:assert/strict";
import { chromium, firefox, webkit } from "playwright";

const HOMESERVER_PUBKY =
  process.env.E2E_HOMESERVER_PUBKY ??
  "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo";
const SIGNUP_TOKEN = process.env.E2E_SIGNUP_TOKEN ?? null;
// Fixed testnet ports the wasm client dials (pubky_common::constants).
const PKARR_RELAY_FIXED_PORT = 15411;
const HOMESERVER_HTTP_FIXED_PORT = 6286;
// Where the live testnet actually listens on this host.
const PKARR_RELAY_HOST_PORT = Number(process.env.E2E_PKARR_RELAY_PORT ?? 25411);
const HOMESERVER_HTTP_HOST_PORT = Number(process.env.E2E_HOMESERVER_HTTP_PORT ?? 16286);
const STATIC_PORT = Number(process.env.E2E_STATIC_PORT ?? 8099);
const HEADLESS = process.env.E2E_HEADED !== "1";
const BROWSER = process.env.E2E_BROWSER ?? "chromium";
const browserTypes = { chromium, firefox, webkit };

// PaykitReceiverPath requires the runtime segment to be 'wallet' or 'server'.
const RECEIVER_PATH = "marketplace/wallet";
const HANDSHAKE_ROUND_LIMIT = 90;
const HANDSHAKE_ROUND_DELAY_MS = 700;
const RECEIVE_POLL_LIMIT = 60;
const RECEIVE_POLL_DELAY_MS = 500;

const here = path.dirname(fileURLToPath(import.meta.url));
const pkgDir = path.resolve(here, "..", "pkg");

let passed = 0;
function ok(name) {
  passed += 1;
  console.log(`ok ${passed} - ${name}`);
}

// --- port bridges -----------------------------------------------------------

const forwardServers = [];

function startForward(listenPort, targetPort) {
  return new Promise((resolve, reject) => {
    const server = createServer((client) => {
      const upstream = new Socket();
      upstream.connect(targetPort, "127.0.0.1");
      client.pipe(upstream);
      upstream.pipe(client);
      const drop = () => {
        client.destroy();
        upstream.destroy();
      };
      client.on("error", drop);
      upstream.on("error", drop);
    });
    server.on("error", (err) => {
      if (err.code === "EADDRINUSE") {
        console.error(
          `warn: port ${listenPort} already in use; assuming a compatible testnet service is listening there`,
        );
        resolve(null);
      } else {
        reject(err);
      }
    });
    server.listen(listenPort, "127.0.0.1", () => {
      forwardServers.push(server);
      console.log(`bridge 127.0.0.1:${listenPort} -> 127.0.0.1:${targetPort}`);
      resolve(server);
    });
  });
}

// --- static harness server ---------------------------------------------------

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".wasm": "application/wasm",
  ".json": "application/json",
  ".ts": "text/plain",
};

function startStaticServer() {
  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, `http://localhost:${STATIC_PORT}`);
      let filePath;
      if (url.pathname === "/" || url.pathname === "/harness.html") {
        filePath = path.join(here, "harness.html");
      } else if (url.pathname.startsWith("/pkg/")) {
        filePath = path.join(pkgDir, url.pathname.slice("/pkg/".length));
      } else {
        filePath = path.join(here, url.pathname.slice(1));
      }
      // Refuse path escapes.
      if (!filePath.startsWith(here) && !filePath.startsWith(pkgDir)) {
        res.writeHead(403).end();
        return;
      }
      const body = await readFile(filePath);
      res.writeHead(200, {
        "content-type": MIME[path.extname(filePath)] ?? "application/octet-stream",
      });
      res.end(body);
    } catch {
      res.writeHead(404).end("not found");
    }
  });
  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(STATIC_PORT, "127.0.0.1", () => resolve(server));
  });
}

// --- environment preflight ---------------------------------------------------

async function preflight() {
  const relay = await fetch(
    `http://127.0.0.1:${PKARR_RELAY_FIXED_PORT}/${HOMESERVER_PUBKY}`,
  );
  assert.equal(
    relay.status,
    200,
    `pkarr relay did not return the homeserver record (status ${relay.status})`,
  );
  const hs = await fetch(`http://127.0.0.1:${HOMESERVER_HTTP_FIXED_PORT}/`);
  assert.equal(hs.status, 200, `homeserver HTTP root returned ${hs.status}`);
}

// --- page helpers -------------------------------------------------------------

async function newHarnessPage(context, label) {
  const page = await context.newPage();
  page.on("console", (msg) => {
    const type = msg.type();
    if (type === "error" || type === "warning") {
      console.error(`[${label} console.${type}] ${msg.text()}`);
    }
  });
  page.on("pageerror", (err) => console.error(`[${label} pageerror] ${err}`));
  await page.goto(`http://localhost:${STATIC_PORT}/harness.html`);
  await page.evaluate(() => window.paykitReady);
  return page;
}

async function setupIdentity(page, { homeserver, signupToken }) {
  return page.evaluate(
    async ({ homeserver, signupToken }) => {
      const p = window.paykit;
      const s = window.state;
      s.client = p.PubkyClient.testnet();
      s.identitySecret = crypto.getRandomValues(new Uint8Array(32));
      s.session = await s.client.signupWithSecret(
        s.identitySecret,
        homeserver,
        signupToken,
      );
      s.noiseSecret = new Uint8Array(p.generateNoiseSecretKey());
      s.noisePublic = p.noisePublicKeyFromSecret(s.noiseSecret);
      return { pubky: s.session.pubky(), noisePublic: s.noisePublic };
    },
    { homeserver, signupToken },
  );
}

async function advanceOnce(page) {
  return page.evaluate(async () => {
    const s = window.state;
    if (s.link) return "complete";
    const result = await s.handshake.advance();
    if (result.status === "complete") {
      s.link = result.link;
      return "complete";
    }
    return result.status;
  });
}

async function linkMeta(page) {
  return page.evaluate(() => {
    const s = window.state;
    return {
      recipient: s.link.recipient(),
      remoteNoisePublicKey: s.link.remoteNoisePublicKey(),
      localReceiverPath: s.link.localReceiverPath(),
      remoteReceiverPath: s.link.remoteReceiverPath(),
      linkId: window.linkIdFromSnapshot(s.link.snapshot()),
    };
  });
}

async function sendMessage(page, payload) {
  return page.evaluate(async (json) => {
    await window.state.link.sendPrivateApplicationMessageJson(json);
  }, JSON.stringify(payload));
}

async function receiveMessages(page, minCount, { pollLimit, pollDelay }) {
  return page.evaluate(
    async ({ minCount, pollLimit, pollDelay }) => {
      const s = window.state;
      const collected = [];
      for (let i = 0; i < pollLimit && collected.length < minCount; i++) {
        const got = await s.link.receivePrivateApplicationMessages();
        for (const m of got) {
          collected.push({ version: m.version, kind: m.kind, rawJson: m.rawJson });
        }
        if (collected.length < minCount) await window.sleep(pollDelay);
      }
      return collected;
    },
    { minCount, pollLimit, pollDelay },
  );
}

// --- main ----------------------------------------------------------------------

async function main() {
  await startForward(PKARR_RELAY_FIXED_PORT, PKARR_RELAY_HOST_PORT);
  await startForward(HOMESERVER_HTTP_FIXED_PORT, HOMESERVER_HTTP_HOST_PORT);
  const staticServer = await startStaticServer();
  console.log(`harness at http://localhost:${STATIC_PORT}/harness.html`);

  await preflight();
  ok("preflight: pkarr relay serves homeserver record; homeserver HTTP reachable");

  const browserType = browserTypes[BROWSER];
  assert.ok(browserType, `unknown E2E_BROWSER '${BROWSER}' (chromium|firefox|webkit)`);
  console.log(`browser: ${BROWSER}`);
  const browser = await browserType.launch({ headless: HEADLESS });
  const cleanup = async () => {
    await browser.close().catch(() => {});
    staticServer.close();
    for (const s of forwardServers) s.close();
  };

  try {
    const aliceCtx = await browser.newContext();
    let bobCtx = await browser.newContext();
    const alice = await newHarnessPage(aliceCtx, "alice");
    let bob = await newHarnessPage(bobCtx, "bob");

    // 1. Sessions via dev keypair signup.
    const aliceId = await setupIdentity(alice, {
      homeserver: HOMESERVER_PUBKY,
      signupToken: SIGNUP_TOKEN,
    });
    const bobId = await setupIdentity(bob, {
      homeserver: HOMESERVER_PUBKY,
      signupToken: SIGNUP_TOKEN,
    });
    assert.match(aliceId.pubky, /^[a-z0-9]{52}$/);
    assert.match(bobId.pubky, /^[a-z0-9]{52}$/);
    assert.notEqual(aliceId.pubky, bobId.pubky);
    ok(`browser signup sessions established (alice=${aliceId.pubky} bob=${bobId.pubky})`);

    // 1b. Session survives a page reload: exportSession() yields secret-free
    // metadata; the credential is the browser's HTTP-only session cookie,
    // which the reload keeps. restoreSession() revalidates against the
    // homeserver. Everything after this step runs on alice's RESTORED
    // session, so the rest of the suite proves it is fully functional.
    const aliceCarryOver = await alice.evaluate(() => {
      const s = window.state;
      return {
        exported: s.session.exportSession(),
        noiseSecret: Array.from(s.noiseSecret),
        noisePublic: s.noisePublic,
      };
    });
    assert.ok(aliceCarryOver.exported.length > 0);
    await alice.reload();
    await alice.evaluate(() => window.paykitReady);
    const restoredAlicePubky = await alice.evaluate(
      async ({ exported, noiseSecret, noisePublic }) => {
        const p = window.paykit;
        const s = window.state;
        s.client = p.PubkyClient.testnet();
        s.session = await s.client.restoreSession(exported);
        s.noiseSecret = new Uint8Array(noiseSecret);
        s.noisePublic = noisePublic;
        return s.session.pubky();
      },
      aliceCarryOver,
    );
    assert.equal(restoredAlicePubky, aliceId.pubky);
    ok("alice session restored after page reload (exported metadata + cookie, no re-approval)");

    const badRestore = await alice.evaluate(async () => {
      try {
        await window.state.client.restoreSession("bm90LWEtc2Vzc2lvbg==");
        return null;
      } catch (err) {
        return String(err);
      }
    });
    assert.ok(
      badRestore !== null && badRestore.includes("session restore failed"),
      `expected a clear restore rejection, got: ${badRestore}`,
    );
    ok("restoring malformed session metadata rejects with a clear error");

    // 1c. Cookie-ONLY resume: reload alice again and DISCARD the exported
    // metadata entirely — `resumeSessionFromCookie` rebuilds the session
    // handle purely from the browser's HTTP-only cookie (the credential the
    // homeserver set at signup). Every subsequent alice check — marker
    // publish, handshake, message exchange — runs on THIS cookie-resumed
    // session, proving it is fully functional, not merely present.
    await alice.reload();
    await alice.evaluate(() => window.paykitReady);
    const cookieResumed = await alice.evaluate(
      async ({ pubky, noiseSecret, noisePublic }) => {
        const p = window.paykit;
        const s = window.state;
        s.client = p.PubkyClient.testnet();
        // No restoreSession input exists here: the exported string was
        // deliberately not carried across this reload.
        s.session = await s.client.resumeSessionFromCookie(pubky);
        s.noiseSecret = new Uint8Array(noiseSecret);
        s.noisePublic = noisePublic;
        return { pubky: s.session.pubky(), exported: s.session.exportSession() };
      },
      {
        pubky: aliceId.pubky,
        noiseSecret: aliceCarryOver.noiseSecret,
        noisePublic: aliceCarryOver.noisePublic,
      },
    );
    assert.equal(cookieResumed.pubky, aliceId.pubky);
    assert.ok(cookieResumed.exported.length > 0);
    ok("alice session resumed PURELY from the cookie (no exported metadata, no re-approval)");

    // The cookie-resumed handle joins the exportSession round-trip: its
    // export string is accepted by restoreSession like any approval-path
    // export would be.
    const roundTrippedPubky = await alice.evaluate(async (exported) => {
      const restored = await window.state.client.restoreSession(exported);
      const restoredPubky = restored.pubky();
      restored.free();
      return restoredPubky;
    }, cookieResumed.exported);
    assert.equal(roundTrippedPubky, aliceId.pubky);
    ok("cookie-resumed session's exportSession round-trips through restoreSession");

    // Typed failure: alice's browser context holds no cookie for bob's
    // pubky, so resuming for it must reject with a machine-readable error
    // name (not a working handle, not an opaque failure).
    const wrongPubkyResume = await alice.evaluate(async (otherPubky) => {
      try {
        const handle = await window.state.client.resumeSessionFromCookie(otherPubky);
        return { resolvedPubky: handle.pubky() };
      } catch (err) {
        return { name: err?.name ?? null, message: String(err) };
      }
    }, bobId.pubky);
    assert.equal(
      wrongPubkyResume.name,
      "SessionResumeUnauthorized",
      `expected a typed SessionResumeUnauthorized rejection, got: ${JSON.stringify(wrongPubkyResume)}`,
    );
    ok("cookie-resume for a pubky the browser holds no cookie for rejects with SessionResumeUnauthorized");

    // 2. Receiver markers: publish on both sides.
    for (const page of [alice, bob]) {
      await page.evaluate(async (receiverPath) => {
        const p = window.paykit;
        const s = window.state;
        await p.publishReceiverMarker(
          s.session,
          receiverPath,
          s.noisePublic,
          true,
          false,
          false,
          false,
        );
      }, RECEIVER_PATH);
    }
    ok("receiver markers published from both browser contexts");

    // 3. Marker discovery across identities (browser -> pkarr -> homeserver).
    const readMarker = (page, owner, receiverPath) =>
      page.evaluate(
        async ({ owner, receiverPath }) => {
          const m = await window.paykit.getReceiverMarker(
            window.state.client,
            owner,
            receiverPath,
          );
          return m === undefined
            ? undefined
            : {
                receiverPath: m.receiverPath,
                noisePublicKey: m.noisePublicKey,
                capabilities: m.capabilities,
              };
        },
        { owner, receiverPath },
      );

    const bobMarkerSeenByAlice = await readMarker(alice, bobId.pubky, RECEIVER_PATH);
    const aliceMarkerSeenByBob = await readMarker(bob, aliceId.pubky, RECEIVER_PATH);
    assert.equal(bobMarkerSeenByAlice.noisePublicKey, bobId.noisePublic);
    assert.equal(aliceMarkerSeenByBob.noisePublicKey, aliceId.noisePublic);
    assert.equal(bobMarkerSeenByAlice.receiverPath, RECEIVER_PATH);
    assert.equal(bobMarkerSeenByAlice.capabilities.privatePayments, true);
    assert.equal(bobMarkerSeenByAlice.capabilities.paymentRequests, false);
    ok("markers discovered cross-identity; noise keys and capabilities match");

    const missingMarker = await readMarker(alice, bobId.pubky, "otherapp/wallet");
    assert.equal(missingMarker, undefined);
    ok("unpublished marker path resolves to undefined (clean None)");

    // Owner PUT / public GET / DELETE. Uses a paykit-connect-shaped path
    // under /pub/ so the new wasm storage bindings are exercised against
    // the local testnet (not production).
    const handoffPath = `/pub/paykit.app/v0/handoff/e2e-${Date.now().toString(16)}`;
    const handoffBody = Array.from(
      new TextEncoder().encode(JSON.stringify({ sb2: "e2e-fixture" })),
    );
    await alice.evaluate(
      async ({ path, body }) => {
        await window.state.session.putPublic(path, new Uint8Array(body));
      },
      { path: handoffPath, body: handoffBody },
    );
    const fetchedHandoff = await bob.evaluate(
      async ({ owner, path }) => {
        const bytes = await window.paykit.publicGet(window.state.client, owner, path);
        return bytes === undefined ? undefined : Array.from(bytes);
      },
      { owner: aliceId.pubky, path: handoffPath },
    );
    assert.deepEqual(fetchedHandoff, handoffBody);
    await alice.evaluate(async (path) => {
      await window.state.session.deletePublic(path);
    }, handoffPath);
    const goneHandoff = await bob.evaluate(
      async ({ owner, path }) => {
        return await window.paykit.publicGet(window.state.client, owner, path);
      },
      { owner: aliceId.pubky, path: handoffPath },
    );
    assert.equal(goneHandoff, undefined);
    ok("putPublic / publicGet / deletePublic round-trip; missing path is undefined");

    // 4. Handshake over homeserver transport.
    await alice.evaluate(
      ({ bobPubky, bobNoise, receiverPath }) => {
        const p = window.paykit;
        const s = window.state;
        s.handshake = p.initiateEncryptedLink(
          s.session,
          s.noiseSecret,
          bobPubky,
          bobNoise,
          receiverPath,
          receiverPath,
          s.client,
        );
      },
      {
        bobPubky: bobId.pubky,
        bobNoise: bobMarkerSeenByAlice.noisePublicKey,
        receiverPath: RECEIVER_PATH,
      },
    );
    await bob.evaluate(
      ({ alicePubky, aliceNoise, receiverPath }) => {
        const p = window.paykit;
        const s = window.state;
        s.handshake = p.acceptEncryptedLink(
          s.session,
          s.noiseSecret,
          alicePubky,
          aliceNoise,
          receiverPath,
          receiverPath,
          s.client,
        );
      },
      {
        alicePubky: aliceId.pubky,
        aliceNoise: aliceMarkerSeenByBob.noisePublicKey,
        receiverPath: RECEIVER_PATH,
      },
    );

    let aliceDone = false;
    let bobDone = false;
    let rounds = 0;
    while ((!aliceDone || !bobDone) && rounds < HANDSHAKE_ROUND_LIMIT) {
      rounds += 1;
      if (!aliceDone) aliceDone = (await advanceOnce(alice)) === "complete";
      if (!bobDone) bobDone = (await advanceOnce(bob)) === "complete";
      if (!aliceDone || !bobDone) {
        await new Promise((r) => setTimeout(r, HANDSHAKE_ROUND_DELAY_MS));
      }
    }
    assert.ok(
      aliceDone && bobDone,
      `handshake did not complete within ${HANDSHAKE_ROUND_LIMIT} rounds (alice=${aliceDone} bob=${bobDone})`,
    );
    ok(`Noise XX handshake completed over homeserver transport in ${rounds} advance round(s)`);

    const aliceLink = await linkMeta(alice);
    const bobLink = await linkMeta(bob);
    assert.equal(aliceLink.recipient, bobId.pubky);
    assert.equal(bobLink.recipient, aliceId.pubky);
    assert.equal(aliceLink.remoteNoisePublicKey, bobId.noisePublic);
    assert.equal(bobLink.remoteNoisePublicKey, aliceId.noisePublic);
    assert.match(aliceLink.linkId, /^[0-9a-f]{64}$/);
    assert.equal(aliceLink.linkId, bobLink.linkId);
    ok(`both sides derived the same link id (${aliceLink.linkId.slice(0, 16)}…)`);

    // 5. Private Application Messages, both directions.
    const aliceMessage = {
      version: 1,
      kind: "marketplace.chat_message.v0",
      event_id: "e2e-alice-0001",
      conversation_id: "listing-42",
      sent_at: new Date().toISOString(),
      body: "Is the item still available? (sent from a real browser)",
    };
    await sendMessage(alice, aliceMessage);
    const bobInbox = await receiveMessages(bob, 1, {
      pollLimit: RECEIVE_POLL_LIMIT,
      pollDelay: RECEIVE_POLL_DELAY_MS,
    });
    assert.equal(bobInbox.length, 1);
    assert.equal(bobInbox[0].version, 1);
    assert.equal(bobInbox[0].kind, "marketplace.chat_message.v0");
    assert.deepEqual(JSON.parse(bobInbox[0].rawJson), aliceMessage);
    ok("alice -> bob message delivered via outbox polling with intact payload");

    const bobReply = {
      version: 1,
      kind: "marketplace.chat_message.v0",
      event_id: "e2e-bob-0001",
      conversation_id: "listing-42",
      sent_at: new Date().toISOString(),
      body: "Yes - happy to answer questions.",
    };
    await sendMessage(bob, bobReply);
    const aliceInbox = await receiveMessages(alice, 1, {
      pollLimit: RECEIVE_POLL_LIMIT,
      pollDelay: RECEIVE_POLL_DELAY_MS,
    });
    assert.equal(aliceInbox.length, 1);
    assert.deepEqual(JSON.parse(aliceInbox[0].rawJson), bobReply);
    ok("bob -> alice message delivered with intact payload");

    // 6. Marker removal round-trips.
    await bob.evaluate(async (receiverPath) => {
      await window.paykit.removeReceiverMarker(window.state.session, receiverPath);
    }, RECEIVER_PATH);
    const removedMarker = await readMarker(alice, bobId.pubky, RECEIVER_PATH);
    assert.equal(removedMarker, undefined);
    ok("receiver marker removal observed from the other browser context");

    // 7. Snapshot -> destroy context -> restore in a fresh context -> receive.
    const bobSnapshot = await bob.evaluate(() =>
      Array.from(window.state.link.snapshot()),
    );
    const bobSecrets = await bob.evaluate(() => ({
      identitySecret: Array.from(window.state.identitySecret),
      noiseSecret: Array.from(window.state.noiseSecret),
    }));
    await bobCtx.close();
    ok("bob link snapshot taken; bob browser context destroyed");

    bobCtx = await browser.newContext();
    bob = await newHarnessPage(bobCtx, "bob-restored");
    const restoredPubky = await bob.evaluate(
      async ({ identitySecret, noiseSecret, alicePubky, receiverPath, snapshot }) => {
        const p = window.paykit;
        const s = window.state;
        s.client = p.PubkyClient.testnet();
        s.session = await s.client.signinWithSecret(new Uint8Array(identitySecret));
        s.link = await p.restoreEncryptedLink(
          s.session,
          new Uint8Array(noiseSecret),
          alicePubky,
          receiverPath,
          receiverPath,
          s.client,
          new Uint8Array(snapshot),
        );
        return s.session.pubky();
      },
      {
        identitySecret: bobSecrets.identitySecret,
        noiseSecret: bobSecrets.noiseSecret,
        alicePubky: aliceId.pubky,
        receiverPath: RECEIVER_PATH,
        snapshot: bobSnapshot,
      },
    );
    assert.equal(restoredPubky, bobId.pubky);
    ok("fresh context signed back in and restored the link from snapshot bytes");

    const postRestoreMessage = {
      version: 1,
      kind: "marketplace.order_update.v0",
      event_id: "e2e-alice-0002",
      conversation_id: "listing-42",
      sent_at: new Date().toISOString(),
      body: "Message sent after your device was wiped and restored.",
    };
    await sendMessage(alice, postRestoreMessage);
    const restoredInbox = await receiveMessages(bob, 1, {
      pollLimit: RECEIVE_POLL_LIMIT,
      pollDelay: RECEIVE_POLL_DELAY_MS,
    });
    assert.equal(restoredInbox.length, 1);
    assert.equal(restoredInbox[0].kind, "marketplace.order_update.v0");
    assert.deepEqual(JSON.parse(restoredInbox[0].rawJson), postRestoreMessage);
    ok("restored context received a NEW message from alice (multi-device survival)");

    // The restored link must also still send.
    const restoredReply = {
      version: 1,
      kind: "marketplace.chat_message.v0",
      event_id: "e2e-bob-0002",
      conversation_id: "listing-42",
      sent_at: new Date().toISOString(),
      body: "Restored device replying.",
    };
    await sendMessage(bob, restoredReply);
    const aliceInbox2 = await receiveMessages(alice, 1, {
      pollLimit: RECEIVE_POLL_LIMIT,
      pollDelay: RECEIVE_POLL_DELAY_MS,
    });
    assert.deepEqual(JSON.parse(aliceInbox2[0].rawJson), restoredReply);
    ok("restored context sent a message alice received (send path survives restore)");

    await alice.evaluate(async () => {
      await window.paykit.signOutSession(window.state.session);
    });
    const afterSignOut = await alice.evaluate(async (pubky) => {
      try {
        await window.state.client.resumeSessionFromCookie(pubky);
        return { ok: true };
      } catch (err) {
        return { ok: false, name: err && err.name, message: String(err) };
      }
    }, aliceId.pubky);
    assert.equal(afterSignOut.ok, false);
    assert.equal(afterSignOut.name, "SessionResumeUnauthorized");
    ok("signOutSession invalidates the cookie; resumeSessionFromCookie is unauthorized");

    console.log(`\n${passed}/${passed} browser e2e checks passed`);
  } finally {
    await cleanup();
  }
}

main().catch((err) => {
  console.error(`\nFAILED after ${passed} passing checks:`);
  console.error(err);
  process.exit(1);
});
