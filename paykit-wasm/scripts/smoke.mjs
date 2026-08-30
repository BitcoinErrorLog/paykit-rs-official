// Smoke test for the paykit-wasm package (wasm-pack --target web output).
//
// Proves, against the actual compiled WASM artifact in ../pkg:
//   1. the module instantiates in a plain JS runtime (Node >= 20),
//   2. the bound messaging API surface is present,
//   3. receiver-scoped Noise key generation works (real entropy via
//      crypto.getRandomValues through getrandom's wasm_js backend),
//   4. a full Noise XX handshake completes between two in-memory parties
//      using the same pubky-noise crypto stack Paykit Encrypted Links use,
//   5. encrypted application messages round-trip in both directions,
//   6. tampered ciphertext fails authentication,
//   7. the 1000-byte message limit is enforced.
//
// No mocks: every assertion below exercises the compiled Rust crypto.

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

import init, {
  PubkyClient,
  AuthFlowHandle,
  SessionHandle,
  LinkHandshakeHandle,
  EncryptedLinkHandle,
  MemoryNoiseSession,
  generateNoiseSecretKey,
  noisePublicKeyFromSecret,
  initiateEncryptedLink,
  acceptEncryptedLink,
  restoreEncryptedLink,
  restoreEncryptedLinkHandshake,
  clearEncryptedLinkOutbox,
  publishReceiverMarker,
  getReceiverMarker,
  removeReceiverMarker,
  setPaymentEndpoint,
  removePaymentEndpoint,
  getPaymentEndpoint,
  getPaymentList,
  listPaymentMethods,
  listPaykitReceiverPaths,
  parsePrivatePaymentListJson,
  serializePrivatePaymentListJson,
  maxNoiseMessageLen,
  noiseTagLen,
  x25519GenerateKeypair,
  sb2VerifySignature,
  sb2Decrypt,
  publicGet,
  signOutSession,
} from "../pkg/paykit_wasm.js";

const wasmPath = fileURLToPath(
  new URL("../pkg/paykit_wasm_bg.wasm", import.meta.url),
);

let passed = 0;
function ok(name, fn) {
  fn();
  passed += 1;
  console.log(`ok ${passed} - ${name}`);
}

// 1. Instantiate the module.
await init({ module_or_path: await readFile(wasmPath) });
ok("module instantiates", () => {});

// 2. Bound API surface is present.
ok("messaging API surface exported", () => {
  for (const fn of [
    generateNoiseSecretKey,
    noisePublicKeyFromSecret,
    initiateEncryptedLink,
    acceptEncryptedLink,
    restoreEncryptedLink,
    restoreEncryptedLinkHandshake,
    clearEncryptedLinkOutbox,
    publishReceiverMarker,
    getReceiverMarker,
    removeReceiverMarker,
    setPaymentEndpoint,
    removePaymentEndpoint,
    getPaymentEndpoint,
    getPaymentList,
    listPaymentMethods,
    listPaykitReceiverPaths,
    parsePrivatePaymentListJson,
    serializePrivatePaymentListJson,
    maxNoiseMessageLen,
    noiseTagLen,
    x25519GenerateKeypair,
    sb2VerifySignature,
    sb2Decrypt,
    publicGet,
    signOutSession,
  ]) {
    assert.equal(typeof fn, "function");
  }
  for (const cls of [
    PubkyClient,
    AuthFlowHandle,
    SessionHandle,
    LinkHandshakeHandle,
    EncryptedLinkHandle,
    MemoryNoiseSession,
  ]) {
    assert.equal(typeof cls, "function");
  }
  assert.equal(typeof EncryptedLinkHandle.prototype.sendPrivateApplicationMessageJson, "function");
  assert.equal(typeof EncryptedLinkHandle.prototype.sendPrivatePaymentList, "function");
  assert.equal(typeof EncryptedLinkHandle.prototype.receivePrivateApplicationMessages, "function");
  assert.equal(typeof EncryptedLinkHandle.prototype.snapshot, "function");
  assert.equal(typeof LinkHandshakeHandle.prototype.advance, "function");
  assert.equal(typeof PubkyClient.prototype.startAuthFlow, "function");
  assert.equal(typeof PubkyClient.prototype.restoreSession, "function");
  assert.equal(typeof PubkyClient.prototype.resumeSessionFromCookie, "function");
  assert.equal(typeof SessionHandle.prototype.exportSession, "function");
  assert.equal(typeof SessionHandle.prototype.putPublic, "function");
  assert.equal(typeof SessionHandle.prototype.deletePublic, "function");
});

// 3. Constants match the pubky-noise wire contract.
ok("noise constants (1000-byte message limit, 16-byte tag)", () => {
  assert.equal(maxNoiseMessageLen(), 1000);
  assert.equal(noiseTagLen(), 16);
});

// 4. Key generation is real entropy and derivation is deterministic.
const aliceNoiseSecret = generateNoiseSecretKey();
const bobNoiseSecret = generateNoiseSecretKey();
ok("receiver noise key generation", () => {
  assert.equal(aliceNoiseSecret.length, 32);
  assert.equal(bobNoiseSecret.length, 32);
  assert.notDeepEqual([...aliceNoiseSecret], [...bobNoiseSecret]);
  const pub1 = noisePublicKeyFromSecret(aliceNoiseSecret);
  const pub2 = noisePublicKeyFromSecret(aliceNoiseSecret);
  assert.equal(pub1, pub2);
  assert.match(pub1, /^[a-z0-9]{52}$/);
  assert.notEqual(pub1, noisePublicKeyFromSecret(bobNoiseSecret));
});

ok("x25519GenerateKeypair is hex and distinct from generateNoiseSecretKey", () => {
  const pair = x25519GenerateKeypair();
  assert.match(pair.publicKey, /^[0-9a-f]{64}$/);
  assert.match(pair.secretKey, /^[0-9a-f]{64}$/);
  assert.notEqual(pair.publicKey, pair.secretKey);
  const other = x25519GenerateKeypair();
  assert.notEqual(pair.secretKey, other.secretKey);
  const noiseHex = Buffer.from(aliceNoiseSecret).toString("hex");
  assert.notEqual(pair.secretKey, noiseHex);
});

// Identity pubkeys for endpoint labelling (z-base-32 Ed25519 keys). These
// stand in for the two parties' Pubky identities; XX does not use them for
// key exchange.
const aliceIdentity = noisePublicKeyFromSecret(generateNoiseSecretKey());
const bobIdentity = noisePublicKeyFromSecret(generateNoiseSecretKey());

// 5. Full Noise XX handshake between two in-memory parties.
const alice = new MemoryNoiseSession(true, aliceNoiseSecret, bobIdentity);
const bob = new MemoryNoiseSession(false, bobNoiseSecret, aliceIdentity);

ok("XX handshake completes and link ids converge", () => {
  // -> e
  bob.readHandshakeMessage(alice.writeHandshakeMessage());
  // <- e, ee, s, es
  alice.readHandshakeMessage(bob.writeHandshakeMessage());
  // -> s, se
  bob.readHandshakeMessage(alice.writeHandshakeMessage());

  assert.equal(alice.isHandshakeComplete(), true);
  assert.equal(bob.isHandshakeComplete(), true);

  alice.transitionTransport();
  bob.transitionTransport();
  assert.equal(alice.isTransport(), true);
  assert.equal(bob.isTransport(), true);

  const aliceLinkId = alice.linkIdHex();
  const bobLinkId = bob.linkIdHex();
  assert.match(aliceLinkId, /^[0-9a-f]{64}$/);
  assert.equal(aliceLinkId, bobLinkId);
});

// 6. Encrypted message roundtrip, both directions, multiple messages.
const encoder = new TextEncoder();
const decoder = new TextDecoder();

ok("encrypted message roundtrip alice -> bob", () => {
  const message = JSON.stringify({
    version: 1,
    kind: "marketplace.chat_message.v0",
    event_id: "5b3f9a0e-8f2c-4f4e-9d35-1c2b4a6d8e01",
    conversation_id: "listing-42",
    sent_at: "2026-08-20T19:00:00Z",
    body: "Is the item still available?",
  });
  const packet = alice.encrypt(encoder.encode(message));
  assert.ok(packet.length > message.length);
  const plaintext = decoder.decode(bob.decrypt(packet));
  assert.equal(plaintext, message);
});

ok("encrypted message roundtrip bob -> alice", () => {
  const reply = JSON.stringify({
    version: 1,
    kind: "marketplace.chat_message.v0",
    event_id: "0d1e2f3a-4b5c-6d7e-8f90-a1b2c3d4e5f6",
    conversation_id: "listing-42",
    sent_at: "2026-08-20T19:01:00Z",
    body: "Yes - happy to answer questions.",
  });
  const packet = bob.encrypt(encoder.encode(reply));
  assert.equal(decoder.decode(alice.decrypt(packet)), reply);
});

ok("nonce sequencing across multiple messages", () => {
  for (let i = 0; i < 5; i++) {
    const text = `message number ${i}`;
    const packet = alice.encrypt(encoder.encode(text));
    assert.equal(decoder.decode(bob.decrypt(packet)), text);
  }
});

// 7. Tampered ciphertext fails AEAD authentication, and the receiving nonce
// is not burned by the failure: re-delivering the original packet (the
// homeserver slot re-read case) still decrypts.
ok("tampered ciphertext is rejected", () => {
  const packet = alice.encrypt(encoder.encode("do not tamper"));
  const tampered = Uint8Array.from(packet);
  tampered[10] ^= 0xff;
  assert.throws(() => bob.decrypt(tampered), /decrypt failed/);
  assert.equal(decoder.decode(bob.decrypt(packet)), "do not tamper");
});

// 8. Message size limit enforcement.
ok("1000-byte limit enforced", () => {
  const exact = new Uint8Array(maxNoiseMessageLen()).fill(0x61);
  const packet = alice.encrypt(exact);
  assert.deepEqual([...bob.decrypt(packet)], [...exact]);
  const oversize = new Uint8Array(maxNoiseMessageLen() + 1).fill(0x61);
  assert.throws(() => alice.encrypt(oversize), /exceeds max Noise message size/);
});

// 9. Homeserver-facing client constructs (no network I/O at construction).
ok("PubkyClient constructs and auth flow yields a pubkyauth URL", () => {
  const client = new PubkyClient();
  const flow = client.startAuthFlow("/pub/paykit/:rw");
  const url = flow.authorizationUrl();
  // e.g. pubkyauth://signin?caps=/pub/paykit/:rw&relay=…&secret=…
  assert.match(url, /^pubkyauth:\/\/signin\?/);
  assert.ok(url.includes("caps=/pub/paykit/:rw"));
  assert.ok(url.includes("relay="));
  assert.ok(url.includes("secret="));
});

// 10. Cookie-resume input validation (no network: an invalid pubky is
// rejected before any request is attempted).
{
  const client = new PubkyClient();
  let rejected = null;
  try {
    await client.resumeSessionFromCookie("not-a-valid-pubky");
  } catch (err) {
    rejected = String(err);
  }
  ok("resumeSessionFromCookie rejects an invalid pubky before any I/O", () => {
    assert.ok(rejected !== null && /invalid pubky public key/.test(rejected), `got: ${rejected}`);
  });
}

ok("private payment list serialize/parse round-trips and rejects reserved ids", () => {
  const json = serializePrivatePaymentListJson({
    lightning: "ln...",
    onchain: "bc1qexample",
  });
  const parsed = parsePrivatePaymentListJson(json);
  assert.equal(parsed.lightning, "ln...");
  assert.equal(parsed.onchain, "bc1qexample");
  const wire = JSON.parse(json);
  assert.equal(wire.version, 1);
  assert.equal(wire.kind, "paykit.private_payment_list");
  assert.throws(
    () => parsePrivatePaymentListJson('{"lightning":"ln..."}'),
    /failed to parse Private Payment List/,
  );
  assert.throws(
    () => serializePrivatePaymentListJson({ private: "secret" }),
    /invalid payment endpoint identifier/,
  );
});

ok("private payment list keeps __proto__ as an own data property", () => {
  // An object literal `{ __proto__: ... }` mutates the prototype; define an
  // own data property so serialize sees the identifier as a real key.
  const input = {};
  Object.defineProperty(input, "__proto__", {
    value: "ln-proto",
    writable: true,
    enumerable: true,
    configurable: true,
  });
  input.lightning = "ln...";
  const json = serializePrivatePaymentListJson(input);
  const parsed = parsePrivatePaymentListJson(json);
  const proto = Object.getOwnPropertyDescriptor(parsed, "__proto__");
  assert.ok(proto && !proto.get && !proto.set, "expected an own data property");
  assert.equal(proto.value, "ln-proto");
  assert.equal(parsed.lightning, "ln...");
  assert.ok(Object.prototype.hasOwnProperty.call(parsed, "__proto__"));
});

ok("getPaymentEndpoint rejects an invalid identifier before any I/O", () => {
  const client = new PubkyClient();
  const knownZ32 = "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo";
  assert.throws(
    () => getPaymentEndpoint(client, knownZ32, "bitkit/wallet", ".."),
    /invalid payment endpoint identifier/,
  );
  assert.throws(
    () => getPaymentList(client, knownZ32, "not-a-receiver"),
    /invalid payment receiver path/,
  );
});

alice.close();
bob.close();

console.log(`\n${passed}/${passed} smoke checks passed`);
