# Paykit Private Application Message Envelope Frame

Status: draft / discussion only
Date: 2026-09-01

## Goal

Define the general envelope frame for application Event Messages sent as Paykit Private Application Messages over an Encrypted Link.

Paykit Encrypted Link already carries arbitrary JSON. This spec is the shared frame so independent apps can coexist on one link, skip vocabularies they do not implement, and interoperate on one canonical direct-message kind. It does not add a chat kind to Paykit, and it does not redefine Paykit payment kinds.

## Scope

This spec defines:

- the envelope object for application Event Messages (`version`, `kind`, `event_id`, `sent_at`)
- kind string rules and namespace reservation
- the 1000-byte serialized size ceiling
- authenticity (Encrypted Link direction; no spoofable sender field)
- unknown-kind delivery vs application handling vs checkpoint policy
- the canonical shared kind `pubky_app.dm.v0`

This spec does not define:

- chat groups
- attachments
- marketplace listing chat (`marketplace.chat_message.v0` and its listing-scoped fields)
- Paykit payment messages (`paykit.*`), including Payment Requests, Payment Proof, Receipt Access, and Private Payment Lists
- Noise handshake
- homeserver paths
- FFI / language bindings
- UI, local database schema, retry policy, or multi-device backup

Paykit protocol kinds remain specified in [`payment-requests.md`](payment-requests.md). This document MUST NOT add, rename, or extend those kinds.

## Transport

All messages in this spec are `pubky-noise` Private Application Messages sent over an established Encrypted Link.

Paykit Library already exposes this as a generic JSON pipe:

- `EncryptedLink::send_private_application_message_json` sends caller-supplied JSON. It validates that `version` is a `u8` integer and `kind` is a string. It does not require a known Paykit kind and does not validate kind-specific bodies.
- `EncryptedLink::receive_private_application_messages` returns `PrivateApplicationMessage` values with open `kind: Option<String>` plus the raw plaintext.
- `PrivateApplicationMessage::known_kind()` recognizes Paykit's own payment kinds only.

Known Paykit kinds, specified elsewhere and unchanged here:

- `paykit.private_payment_list`
- `paykit.receipt_access`
- `paykit.payment_request`
- `paykit.payment_request_acceptance`
- `paykit.payment_request_rejection`
- `paykit.payment_request_cancellation`
- `paykit.payment_proof`

Application messages that follow this envelope are Event Messages: every valid message matters, receivers MUST preserve send order, and `event_id` is for idempotent storage and replay dedupe.

Private Payment Lists remain Latest-State Messages and are out of scope.

## Envelope object

Application Event Messages that use this frame are a single UTF-8 JSON object:

```json
{
  "version": 1,
  "kind": "pubky_app.dm.v0",
  "event_id": "8a0d8b4c-913f-4e31-9f2c-2a6f5bb4d101",
  "sent_at": 1756742400000
}
```

Kind-specific fields (for example `body` on `pubky_app.dm.v0`) are added only by the kind that defines them.

### Fields

| Field | JSON type | Rule |
| --- | --- | --- |
| `version` | number | MUST be the integer `1` (a `u8`). String `"1"` is invalid. |
| `kind` | string | MUST be a non-empty ASCII kind string as defined below. |
| `event_id` | string | MUST be a sender-minted UUID in 8-4-4-4-12 hexadecimal form. |
| `sent_at` | number | MUST be a positive Unix timestamp in milliseconds, as an integer JSON number. |

Rules:

- `version` versions this envelope frame. It is currently `1`. A future incompatible frame would increment `version`.
- `kind` identifies the payload vocabulary. Application kinds MUST use reverse-DNS-style labels and a `.vN` suffix. Changing a kind's fields requires a new kind string (`….v1`), not a `version` bump.
- `event_id` identifies one Event Message. Senders SHOULD mint UUID version 4, matching Paykit Payment Request Event Messages. Receivers MUST treat `event_id` comparison as case-insensitive hex.
- A retried resend of the same event MUST reuse the same `event_id` and the same payload bytes.
- Reusing the same `event_id` with different payload bytes on the same link and kind is invalid.
- Receivers MUST dedupe by `(link-direction, kind, event_id)`. Link-direction is the authenticated Encrypted Link pair and which party sent the message. The same UUID on a different link or a different `kind` is a different message.
- `sent_at` is the sender's wall clock. It is for display ordering only. Delivery order is Encrypted Link stream order. Receivers MUST NOT treat `sent_at` as proof of send time or as a substitute for stream order.
- `sent_at` MUST be a JSON number with no fractional part and MUST be greater than `0`.
- `sent_at` MUST NOT be a string. ISO-8601 / RFC 3339 timestamps are invalid on this frame. Implementations that currently emit ISO-8601 MUST migrate to Unix-millisecond integers. A receive-side ISO compatibility shim is a local migration aid, not a protocol option. New implementations MUST NOT emit or require ISO `sent_at`.

Invalid examples for `sent_at`:

```json
"sent_at": "2026-09-01T16:50:00.000Z"
"sent_at": "1756742400000"
"sent_at": 1756742400
```

The first is ISO-8601. The second is a numeric timestamp encoded as a string. The third is Unix seconds, not milliseconds. All three MUST be rejected on this frame.

## Kind strings

`kind` MUST be a non-empty ASCII string of one or more labels separated by `.`.

```text
label      = 1*( %x61-7A / DIGIT / "_" )   ; a-z, 0-9, underscore
app-kind   = 1*( label "." ) label ".v" 1*DIGIT
```

Rules:

- `kind` MUST NOT contain spaces, uppercase, hyphens, or control characters.
- Application kinds (every kind not under `paykit.`) MUST match `app-kind` and therefore end with `.vN`, where `N` is a non-negative integer.
- Paykit protocol kinds under `paykit.` are specified in [`payment-requests.md`](payment-requests.md). They do not use a `.vN` suffix; they are versioned by the envelope `version` field of those messages. This spec does not change them.

### Namespaces

| Prefix | Owner | Rule |
| --- | --- | --- |
| `paykit.` | Paykit protocol | Reserved. Applications MUST NOT mint new `paykit.*` kinds. Existing kinds stay as listed above. |
| `pubky_app.` | Cross-app general kinds | Reserved for kinds meant to be implemented by more than one app. New `pubky_app.*` kinds are a shared-vocabulary decision, not an app-private mint. |
| Other prefixes (`chat.`, `marketplace.`, …) | App-private | Legal on the same Encrypted Link. Other apps MUST treat them as unknown kinds unless they implement that app's vocabulary. |

`chat.message.v0` and `marketplace.chat_message.v0` are app-private examples. They are not specified here.

## Size

The Noise XX transport uses a fixed `pubky_noise` buffer (`PUBKY_NOISE_MSG_LEN` / `maxNoiseMessageLen()`), currently 1000 bytes.

Rules:

- The exact UTF-8 bytes passed to `send_private_application_message_json` MUST be valid JSON and MUST be less than or equal to 1000 bytes.
- The ceiling applies to the entire serialized envelope, not to `body` alone.
- Applications MUST fail closed on oversize. They MUST NOT truncate, drop characters, or otherwise mutate user content to fit.
- Whitespace, JSON escaping, and multi-byte UTF-8 all count. Senders MUST measure the exact bytes they send. This spec does not require a canonical JSON serializer.

Paykit Library already rejects plaintext larger than `PUBKY_NOISE_MSG_LEN` before encryption. Applications SHOULD reject oversize envelopes before calling send so the failure is an application validation error, not a transport error.

## Authenticity

The Encrypted Link identifies the local party and the counterparty. Stream direction identifies the sender.

Rules:

- The envelope MUST NOT include `sender`, `from`, `author`, or any other spoofable identity field.
- `pubky_app.dm.v0` MUST NOT include those fields.
- Application kinds SHOULD NOT add a sender field. The authenticated link direction is the sender.
- Receivers MUST attribute a message to the Encrypted Link counterparty that sent it, not to any JSON field.

## Unknown kinds

Paykit transport delivers every decrypted Private Application Message, including kinds the local app does not implement.

Rules:

- An unknown `kind` is not a Paykit protocol error. It MUST NOT fail the Encrypted Link, tear down the session, or skip subsequent messages in the same receive batch.
- Paykit itself MUST NOT require applications to drop unknown kinds. `known_kind()` returning `None` means "not a Paykit payment kind", not "illegal".
- Applications decide persist-versus-skip for their own vocabulary. Ignoring a kind for application processing (do not render it, do not decode it as a DM) is allowed.
- Ignoring a kind for application processing is not the same as advancing a durable Encrypted Link checkpoint.

If the application persists Encrypted Link snapshots (or any equivalent Noise read counter) as its receive checkpoint:

- Paykit receive APIs advance the Noise read checkpoint past the returned batch.
- The application MUST persist the delivered plaintext, or otherwise durably record that the stream item was received, before replacing a stored snapshot with one whose read counter has advanced past that item.
- Advancing the checkpoint without that record drops the message. Unknown kinds are the usual casualty: the app did not decode them, so it did not store them, and a snapshot write then makes them unrecoverable.
- A crash after persistence but before snapshot persistence may replay messages. Receivers MUST dedupe replayed Event Messages by `(link-direction, kind, event_id)`.

Applications that do not persist snapshots follow their own local store policy. This spec does not require every app to keep unknown kinds forever. It requires that a checkpoint which forgets a delivered message not be treated as successful consumption of that message.

## Canonical shared kind: `pubky_app.dm.v0`

This is the kind Hypercolor and marketplace already share by name. They MUST align on this shape.

```json
{
  "version": 1,
  "kind": "pubky_app.dm.v0",
  "event_id": "8a0d8b4c-913f-4e31-9f2c-2a6f5bb4d101",
  "sent_at": 1756742400000,
  "body": "hello"
}
```

| Field | JSON type | Rule |
| --- | --- | --- |
| `version` | number | MUST be `1`. |
| `kind` | string | MUST be `pubky_app.dm.v0`. |
| `event_id` | string | MUST be a UUID, as in the envelope frame. |
| `sent_at` | number | MUST be a Unix-millisecond integer, as in the envelope frame. |
| `body` | string | MUST be non-empty after trim. Senders MUST trim before serialize. |

Rules:

- `pubky_app.dm.v0` is a closed-world JSON object. Unknown fields are invalid.
- `body` MUST NOT be null, a number, or an empty string. Whitespace-only `body` is invalid.
- There is no `conversation_id`. Conversation identity is the Encrypted Link counterparty.
- There is no `listing_ref`. Listing-scoped chat is app-private and out of scope.
- Apps that want cross-app direct-message interop MUST emit this kind with this shape. Emitting only an app-private kind (`chat.message.v0`, `marketplace.chat_message.v0`, or any other) is not interop on this kind.

## Appendix: Current implementations

This appendix is observational. It is not a second protocol.

| Implementation | Kind | `sent_at` on the wire | Status |
| --- | --- | --- | --- |
| Hypercolor (`src/types/link.ts`) | Emits `chat.message.v0`. Decodes `pubky_app.dm.v0` as well. | Unix-millisecond integer (`number`) | Compliant with this frame's `sent_at` type. `LINK_MESSAGE_MAX_BYTES = 1000`. Unknown kinds are stored, not treated as errors. Sender is not a field. Does not currently emit the shared kind `pubky_app.dm.v0`. |
| Marketplace (`src/libs/messaging/dm-contracts.ts`) | Emits `pubky_app.dm.v0`. | ISO-8601 datetime string (`z.iso.datetime()`) | Non-compliant. Same kind string as the shared DM kind, incompatible `sent_at` type. This is the interop bug. Marketplace MUST migrate emitters and decoders to Unix-millisecond integers. `PAYKIT_NOISE_MESSAGE_MAX_BYTES = 1000`. Listing chat `marketplace.chat_message.v0` is app-private and out of scope; it currently also uses ISO-8601. |

Until marketplace migrates, a peer that rejects ISO `sent_at` on `pubky_app.dm.v0` will not decode marketplace DMs. That rejection is correct for this frame. The required fix is marketplace emission, not a protocol exception for ISO strings.
