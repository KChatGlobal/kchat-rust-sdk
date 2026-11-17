# Node.js binding for Rust KChat SDK

This crate provides unified bindings for the KChat MLS and backup Rust SDKs using [NAPI-RS](https://napi.rs/).
The Node.js package is `@kchat/napi`. The existing `@kchat/mls-napi` package remains available.

## Prerequisites

- Install stable `Rust` with support for edition 2024.
- Install `Node.js@22.13+` as required by this package.
- Install `yarn@4.x` (the crate uses `yarn@4.9.1` via Corepack).
- The `napi` CLI is included in the development dependencies.

## Setup

1. **Project Structure**

   The crate has the following structure (`index.js` and `index.d.ts` are generated during the build):

   ```text
   .
   ├── .cargo
   │   └── config.toml
   ├── scripts
   │   ├── install.js
   │   └── version.js
   ├── src
   │   ├── backup
   │   │   ├── error.rs
   │   │   ├── io.rs
   │   │   ├── key.rs
   │   │   └── mod.rs
   │   ├── file_crypto
   │   │   ├── error.rs
   │   │   ├── handles.rs
   │   │   ├── io.rs
   │   │   ├── keyring.rs
   │   │   ├── mod.rs
   │   │   └── types.rs
   │   ├── mls
   │   │   ├── error.rs
   │   │   └── mod.rs
   │   └── lib.rs
   ├── build.rs
   ├── Cargo.toml
   ├── index.d.ts
   ├── index.js
   └── package.json
   ```

   - `Cargo.toml`: Configures the Rust crate and dependencies.
   - `src/lib.rs`: Registers the `backup` and `mls` modules, following `kchat-uniffi`.
   - `src/backup/key.rs`: Exposes backup key and descriptor APIs.
   - `src/backup/io.rs`: Exposes streaming encryption and decryption APIs.
   - `src/file_crypto/`: Exposes `kchat-file-crypto` (see [File crypto](#file-crypto)).
   - `src/mls/mod.rs`: Exposes MLS APIs, including `UqMls`.
   - Each module has its own `error.rs` for converting Rust errors to Node.js errors.
   - `index.js`: Loads the native binding for the current platform.
   - `index.d.ts`: Contains the generated TypeScript declarations.

2. **Write Rust Code to Be Called from Node.js**

   Decorate a Rust function with `#[napi]`:

   ```rust
   #[napi]
   pub fn sum(a: u32, b: u32) -> u32 {
       a + b
   }
   ```

   For more information, visit [NAPI-RS exports](https://napi.rs/docs/concepts/exports).

3. **Build**

   Run from this crate's directory within the repository:

   ```sh
   corepack yarn install
   corepack yarn build
   ```

   The build generates `index.js`, `index.d.ts` and the platform-specific `.node` binary.
   Run `corepack yarn build` again after changing Rust code or removing generated files;
   Yarn may skip the install hook when dependencies have not changed.

   Both domains are exported from the same package:

   ```js
   const { UqMls, generatePassword, sealBackupObjectV1 } = require('@kchat/napi');
   ```

   Existing backup callers should replace `@kchat/backup-napi` with `@kchat/napi`.
   API names and arguments are unchanged. The crate uses Yarn's `node-modules` linker
   for compatibility with the NAPI build tools.

## File crypto

`src/file_crypto` exposes [`kchat-file-crypto`](../kchat-file-crypto) to JS hosts. The binding only
converts types; every check stays in the Rust crate. No API returns a DEK, pepper, blind or
NodeKey: JS holds opaque handles (`ContentPlan`, `ContentKey`, `OpenedBlob`, `OprfSession`) and
encrypted records. The only key-bearing bytes are `OutgoingControlMessage.bytes`, which the host
passes straight to MLS.

```js
const sdk = require('@kchat/napi');

const keyring = sdk.FileKeyring.open(path, dbKey /* 32 bytes */, accountId, kkeyRootPublicKey);
keyring.importPublicKey(tenant, keyGen, publicKey, signature);
keyring.importPolicy(tenant, policyVersion, 'HYBRID', signature);

// Upload: two read passes over the same source.
const hash = await sdk.hashContent(operationId, read);
let plan = keyring.preparedPlan(hash);               // resume after a crash
if (!plan) {
  const { session, request } = keyring.beginOprf(tenant, [hash]);
  const response = await kkey.evaluate(request);     // host calls the key service
  [plan] = keyring.finishOprf(session, response);    // or keyring.planRandom(hash, reason)
}
const sealed = await sdk.sealContent(plan, read, sink);
const { fileKey, link } = keyring.createFileKey(root, fileId);  // server stores link, then:
keyring.activateNodeKey(fileKey);
const descriptor = keyring.sealDescriptor(fileKey, fileId, blobId, objectId,
  sdk.ContentKey.fromSealed(plan, sealed), appManifest);
keyring.forgetOperation(operationId);                // after the descriptor is committed

// Download.
keyring.openFileKey(link);
const opened = keyring.openDescriptor(tenant, fileId, descriptor);
await sdk.openContent(opened.contentKey(), read, sink);
```

- `read(maxBytes)` returns `Promise<Buffer>` of at most `maxBytes` (`FILE_CRYPTO_MAX_IO_CHUNK_BYTES`);
  an empty buffer is EOF. `sink` is `{ write(chunk), commit(), abort() }`, each returning a
  Promise and called with `this` bound to the sink. Output may only be used after `commit()`;
  `abort()` means discard everything written. A `FileCryptoCancellation` can cancel the stream.
- `FileKeyring` methods are synchronous (local SQLCipher, no network). `processControl` and
  `buildKeySyncResponse` call `authority` (`allow`, `publishedPepperCommitment`,
  `publishedRootKeyHash`) synchronously; an exception thrown there is rethrown and nothing is
  stored.
- Generations, epochs and lengths are JS numbers; only safe non-negative integers are accepted.
- Errors are `Error`s whose `code` is stable and maps one-to-one to `FileCryptoErrorCode`:
  `INVALID_ARGUMENT`, `UNSUPPORTED_PROFILE`, `PEPPER_REQUIRED`, `KEY_CONFIG_REQUIRED`,
  `PROFILE_NOT_ALLOWED`, `KKEY_PROOF_INVALID`, `KKEY_SIGNATURE_INVALID`, `KEY_CONFLICT`,
  `INTEGRITY_ERROR`, `OPERATION_CONFLICT`, `SOURCE_CHANGED`, `INVALID_STORE_KEY`,
  `ACCOUNT_MISMATCH`, `MALFORMED_MESSAGE`, `UNAUTHORIZED_SENDER`, `WRONG_RECIPIENT`,
  `STORE_ERROR`, `RESOURCE_LIMIT_EXCEEDED`, `CANCELLED`, `IO_ERROR`, `INVALID_STATE`,
  `KEY_SYNC_REQUIRED`, `KEY_ENVELOPE_INVALID`, `POLICY_VIOLATION`. The message is `[CODE] text`.

### End-to-end test

```sh
corepack yarn build
corepack yarn test:file-crypto
```

`tests/file-crypto.e2e.test.mjs` runs the generated binding against a key service written in JS
(VOPRF ristretto255-SHA512 from `@noble/curves`, an RFC 9497 implementation independent of the
SDK's `voprf` crate, and Ed25519 from `node:crypto`). It covers signed key configuration, pepper
bootstrap and distribution over control messages, group root key CAS and distribution, a hybrid
upload with resume, descriptor sealing, download on another member's device, cross-device dedup,
tampering, key sync for a new member, the random fallback, source changes, cancellation, stable
error codes and that handles expose no key material. Set `KCHAT_NAPI_TEST_ADDON` to test another
binary.

### Against real servers

`tests/e2e_test.js` runs the same flow as the Go client's `fileclient/e2e_test.go` against the
e2ee service (KKey and pepper directory), KFiles and KStorage. Device A uploads two versions of a
file into a new group, and device B decrypts them after receiving the root key as a control message.
The test runs once with KKey (hybrid, dedup) and once with the random fallback.

```sh
KCHAT_ACCESS_TOKEN=<jwt> corepack yarn test:e2e
```

The tenant and account come from the token's `tenantId` and `sub` claims; without a valid token the
test is skipped. `KCHAT_E2EE_URL` (default `https://dev-kchat-api.qualgo.dev/e2ee`, including the
`/e2ee` prefix; `http://0.0.0.0:8085` for a local e2ee), `KCHAT_KFILE_URL` (default
`https://dev-kchat-alb.qualgo.dev`) and `KKEY_ROOT_PUBLIC_KEY` (base64 Ed25519 key that signs the KKey
configuration, logged by e2ee at startup as `root_public_key`) select the servers.
