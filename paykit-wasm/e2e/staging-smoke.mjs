// Chromium staging smoke for paykit-wasm managed SDK + IndexedDB.
//
// Proves, against homeserver.staging.pubky.app and a real Chromium
// IndexedDB (not a StorageAdapter mock):
//   1. PubkyClient() signupWithSecret sessions
//   2. owner-scoped IndexedDB state blob round-trip across handle reconstruct
//   3. PaykitSdkHandle.ensureLinkWithPeer converges to Linked
//   4. snapshot export/probe
//
// Usage (from this directory):
//   STAGING_TOKEN_A=... STAGING_TOKEN_B=... node staging-smoke.mjs
// Playwright is resolved from NODE_PATH or PLAYWRIGHT_MODULE.

import http from "node:http";
import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import assert from "node:assert/strict";

const require = createRequire(import.meta.url);
const playwrightModule =
  process.env.PLAYWRIGHT_MODULE ?? "playwright";
const { chromium } = require(playwrightModule);

const HOMESERVER_PUBKY =
  process.env.STAGING_HOMESERVER_PUBKY ??
  "ufibwbmed6jeq9k4p583go95wofakh9fwpp4k734trq79pd9u1uy";
const TOKEN_A = process.env.STAGING_TOKEN_A ?? null;
const TOKEN_B = process.env.STAGING_TOKEN_B ?? null;
const STATIC_PORT = Number(process.env.STAGING_SMOKE_PORT ?? 8098);
const RECEIVER_PATH = "sdk/wallet";
const HANDSHAKE_ROUND_LIMIT = 90;
const HANDSHAKE_ROUND_DELAY_MS = 700;
const HEADLESS = process.env.E2E_HEADED !== "1";

const here = path.dirname(fileURLToPath(import.meta.url));
const pkgDir = path.resolve(here, "..", "pkg");

let passed = 0;
function ok(name) {
  passed += 1;
  console.log(`ok ${passed} - ${name}`);
}

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".wasm": "application/wasm",
  ".json": "application/json",
};

function startStaticServer() {
  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, `http://127.0.0.1:${STATIC_PORT}`);
      let filePath;
      if (url.pathname === "/" || url.pathname === "/harness.html") {
        filePath = path.join(here, "harness.html");
      } else if (url.pathname.startsWith("/pkg/")) {
        filePath = path.join(pkgDir, url.pathname.slice("/pkg/".length));
      } else {
        filePath = path.join(here, url.pathname.slice(1));
      }
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

async function newHarnessPage(context, label) {
  const page = await context.newPage();
  page.on("console", (msg) => {
    const type = msg.type();
    if (type === "error" || type === "warning" || type === "log") {
      console.error(`[${label} console.${type}] ${msg.text()}`);
    }
  });
  page.on("pageerror", (err) => console.error(`[${label} pageerror] ${err}`));
  await page.goto(`http://127.0.0.1:${STATIC_PORT}/harness.html`);
  await page.evaluate(() => window.paykitReady);
  return page;
}

async function setupIdentity(page, { homeserver, signupToken }) {
  return page.evaluate(
    async ({ homeserver, signupToken }) => {
      const p = window.paykit;
      const s = window.state;
      s.client = new p.PubkyClient();
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

async function constructManagedSdk(page, receiverPath) {
  return page.evaluate(async (receiverPath) => {
    const p = window.paykit;
    const s = window.state;
    try {
      s.managedSdk = new p.PaykitSdkHandle(
        s.session,
        s.client,
        s.noiseSecret,
        receiverPath,
      );
      return await s.managedSdk.initialize();
    } catch (err) {
      throw new Error(`PaykitSdkHandle initialize failed: ${err}`);
    }
  }, receiverPath);
}

async function ensureManagedLink(page, counterparty, receiverPath) {
  return page.evaluate(
    async ({ counterparty, receiverPath }) =>
      await window.state.managedSdk.ensureLinkWithPeer(
        counterparty,
        receiverPath,
        2,
      ),
    { counterparty, receiverPath },
  );
}

async function indexedDbStateRecord(page, owner) {
  return page.evaluate(async (owner) => {
    const database = await new Promise((resolve, reject) => {
      const open = indexedDB.open("hypercolor-paykit-sdk", 1);
      open.onsuccess = () => resolve(open.result);
      open.onerror = () => reject(open.error);
    });
    try {
      const transaction = database.transaction("state", "readonly");
      const record = await new Promise((resolve, reject) => {
        const request = transaction.objectStore("state").get(owner);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      return record === undefined
        ? undefined
        : { byteLength: record.blob.byteLength, revision: record.revision };
    } finally {
      database.close();
    }
  }, owner);
}

async function main() {
  assert.ok(TOKEN_A, "STAGING_TOKEN_A is required");
  assert.ok(TOKEN_B, "STAGING_TOKEN_B is required");
  const dts = await readFile(path.join(pkgDir, "paykit_wasm.d.ts"), "utf8");
  assert.match(dts, /export class PaykitSdkHandle/);
  ok("pkg exports PaykitSdkHandle");

  const staticServer = await startStaticServer();
  const chromePath = process.env.CHROME_PATH;
  const browser = await chromium.launch({
    headless: HEADLESS,
    executablePath: chromePath || undefined,
  });
  const cleanup = async () => {
    await browser.close().catch(() => {});
    staticServer.close();
  };

  try {
    const aliceCtx = await browser.newContext();
    const bobCtx = await browser.newContext();
    const alice = await newHarnessPage(aliceCtx, "alice");
    const bob = await newHarnessPage(bobCtx, "bob");

    const aliceId = await setupIdentity(alice, {
      homeserver: HOMESERVER_PUBKY,
      signupToken: TOKEN_A,
    });
    const bobId = await setupIdentity(bob, {
      homeserver: HOMESERVER_PUBKY,
      signupToken: TOKEN_B,
    });
    assert.match(aliceId.pubky, /^[a-z0-9]{52}$/);
    assert.match(bobId.pubky, /^[a-z0-9]{52}$/);
    assert.notEqual(aliceId.pubky, bobId.pubky);
    ok(`staging signup (alice=${aliceId.pubky} bob=${bobId.pubky})`);

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
    ok("receiver markers published");

    const [aliceInitialized, bobInitialized] = await Promise.all([
      constructManagedSdk(alice, RECEIVER_PATH),
      constructManagedSdk(bob, RECEIVER_PATH),
    ]);
    assert.equal(aliceInitialized.publicKey, aliceId.pubky);
    assert.equal(bobInitialized.publicKey, bobId.pubky);
    const aliceState = await indexedDbStateRecord(alice, aliceId.pubky);
    const bobState = await indexedDbStateRecord(bob, bobId.pubky);
    assert.ok(aliceState?.byteLength > 0 && aliceState?.revision);
    assert.ok(bobState?.byteLength > 0 && bobState?.revision);
    ok("IndexedDB state blobs written");

    await Promise.all([
      constructManagedSdk(alice, RECEIVER_PATH),
      constructManagedSdk(bob, RECEIVER_PATH),
    ]);
    const aliceState2 = await indexedDbStateRecord(alice, aliceId.pubky);
    assert.equal(aliceState2.revision, aliceState.revision);
    ok("IndexedDB revision survives handle reconstruct");

    let managedAlice;
    let managedBob;
    for (let round = 0; round < HANDSHAKE_ROUND_LIMIT; round += 1) {
      [managedAlice, managedBob] = await Promise.all([
        ensureManagedLink(alice, bobId.pubky, RECEIVER_PATH),
        ensureManagedLink(bob, aliceId.pubky, RECEIVER_PATH),
      ]);
      if (managedAlice.state === "Linked" && managedBob.state === "Linked") {
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, HANDSHAKE_ROUND_DELAY_MS));
    }
    assert.equal(managedAlice?.state, "Linked");
    assert.equal(managedBob?.state, "Linked");
    ok("ensureLinkWithPeer Linked on staging");

    await Promise.all([
      constructManagedSdk(alice, RECEIVER_PATH),
      constructManagedSdk(bob, RECEIVER_PATH),
    ]);
    const [alicePeers, bobPeers] = await Promise.all([
      alice.evaluate(async () => await window.state.managedSdk.linkedPeers()),
      bob.evaluate(async () => await window.state.managedSdk.linkedPeers()),
    ]);
    assert.equal(alicePeers[0]?.state, "Linked");
    assert.equal(alicePeers[0]?.counterparty, bobId.pubky);
    assert.equal(bobPeers[0]?.state, "Linked");
    assert.equal(bobPeers[0]?.counterparty, aliceId.pubky);
    ok("linked peer reloads from IndexedDB");

    const snapshot = await alice.evaluate(
      async ({ counterparty, receiverPath }) => {
        const bytes = await window.state.managedSdk.exportEncryptedLinkSnapshot(
          counterparty,
          receiverPath,
        );
        window.paykit.PaykitSdkHandle.probeEncryptedLinkSnapshot(bytes);
        return bytes?.length ?? 0;
      },
      { counterparty: bobId.pubky, receiverPath: RECEIVER_PATH },
    );
    assert.ok(snapshot > 0);
    ok(`snapshot export/probe (${snapshot} bytes)`);

    const observed = await bob.evaluate(
      async ({ counterparty, receiverPath }) =>
        await window.state.managedSdk.observeEncryptedLinkRecoveryMarker(
          counterparty,
          receiverPath,
        ),
      { counterparty: aliceId.pubky, receiverPath: RECEIVER_PATH },
    );
    assert.equal(observed.state, "Linked");
    ok("observe recovery marker on live link");

    console.log(`\n${passed}/${passed} staging Chromium checks passed`);
  } finally {
    await cleanup();
  }
}

main().catch((err) => {
  console.error(`\nFAILED after ${passed} passing checks:`);
  console.error(err);
  process.exit(1);
});
