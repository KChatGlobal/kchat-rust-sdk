# kchat-file-crypto

File encryption core. The crate never performs network I/O: the host fetches the signed key
configuration, forwards blinded requests to the key service and returns the responses. Tenant
peppers, verified key configuration and in-flight plans live in an SQLCipher key store
(`FileKeyring`). Content keys, peppers, blinds and VOPRF outputs never leave the crate.

## Upload flow

```text
host                                       kchat-file-crypto
────                                       ─────────────────
FileKeyring::open(path, db_key,        ──► encrypted store bound to the account
                  account_id, root)
import_public_key / import_policy      ──► verify signatures, reject rollback (persisted)
hash_content(operation_id, source)     ──► ContentHash             first read pass
prepared_plan(content)                 ──► stored plan on resume, else:
begin_oprf(tenant, [content])          ──► OprfSession + OprfRequest
  Evaluate(request) at key service
finish_oprf(session, response)         ──► [ContentPlan]           verify, derive, persist
  or plan_random(content, reason)      ──► ContentPlan             labelled fallback, persisted
seal_content(plan, source, sink)       ──► SealedContent           second read pass
forget_operation(operation_id)             after the descriptor is committed
```

`seal_content` commits the sink only when the source still matches the first pass; hosts must not
send any output before it returns `Ok`. Plans are immutable per operation id: a retry after a
crash, or after the key generation rotated, reproduces the same bytes without the key service.

## Peppers

```text
generate_pepper(tenant, generation)  ──► commitment, pending      host runs the server CAS
activate_pepper(tenant, generation)       won the CAS
discard_pepper(tenant, generation)        lost the CAS (pending only)
import_pepper(tenant, generation,         received pepper, stored active only if the
              pepper, commitment)         commitment matches; replaces a pending candidate
```

The highest active generation is used for new plans. The pepper value is never returned, except
inside the bytes of a control message meant for MLS (below).

## Control messages

A device holding an active pepper shares it with other devices through a control message that the
host sends over MLS. The bytes contain the pepper: hosts treat them as opaque, never parse or log
them, and keep them only in encrypted storage until processed.

```text
build_pepper_distribution(tenant,      ──► OutgoingControlMessage   active peppers only
                          generation,
                          recipient)
  host: send as_bytes() over MLS; on receipt check is_control_message and persist the bytes
process_control(sender, local_device,  ──► PepperImported | AlreadyProcessed     then ACK
                bytes, authority)

bytes = "KSTC" || u8 version (= 1) || CBOR {
          "type":      "PepperDistribution",
          "event_id":  bytes(16),
          "tenant":    text,
          "recipient": { "account": text, "device"?: text },
          "body":      { "generation": uint, "pepper": bytes(32), "commitment": bytes(32) } }
```

`process_control` checks, in order:

1. Strict decoding (size, magic, version, type, unknown or duplicate fields, byte-string lengths,
   trailing bytes, body commitment matching the pepper): `MalformedMessage` or `UnsupportedProfile`.
2. The recipient is the store's account, and this device when one is named: `WrongRecipient`.
3. An already processed `event_id` returns `AlreadyProcessed` without asking the host again.
4. `ControlAuthority::allow(sender, request)`, where `sender` is the MLS-authenticated identity:
   `UnauthorizedSender`.
5. `ControlAuthority::published_pepper_commitment` must equal the message commitment:
   `KeyConfigRequired` when unavailable (retry later), `KeyConflict` when different.
6. One transaction stores the pepper as active and records the `event_id`.

The authority is called without holding the store lock, so it may call back into `FileKeyring`.
`MalformedMessage`, `WrongRecipient`, `UnauthorizedSender` and `KeyConflict` are permanent: the host
acknowledges and drops the message. `KeyConfigRequired` and `StoreError` are transient: the host
keeps the bytes and retries.

## Key tree

Flat tree: each group (or a user's personal drafts) is a root, files are leaves. Folders have no
keys.

```text
root key (epoch e) ──wrap──► File NodeKey (generation = e) ──encrypt──► descriptor ──► DEK
```

- Root keys (group NodeKey, personal root) are random, travel only through MLS control messages, and
  are versioned by epoch: 0 on creation (as KFiles `CreateRootKey`), +1 on every rotation. The
  server stores only their `key_hash`, used for the rotation CAS and checked by receivers.
- A File NodeKey is random, wrapped by the root key of the current epoch into a `NodeLink` that the
  server stores. Its generation is KFiles' `file_epoch`, counted apart from the root: 0 on CREATE,
  +1 on ROTATE. The first write after the root rotated rotates the file key; otherwise
  `create_file_key` returns the key in use. A link rebuilt from KFiles has no `key_hash` (the server
  does not return `key_commitment`): `open_file_key` then relies on the AEAD and computes it.
- Each blob is exactly one object. The File NodeKey encrypts its descriptor directly; the
  descriptor carries the object id, its DEK and an optional app manifest. There is no per-blob key
  and no `EncryptedSetKey` (descriptor v2).

```text
record   = nonce (24) || XChaCha20-Poly1305 ciphertext || tag (16)
link AAD = encode("kchat-storage/node-link/v1", tenant, parent_id, u64(parent_gen),
                  u8(parent_kind), child_id, u64(child_gen), u8(child_kind))
           kinds: 1 personal root, 2 group root, 3 file
key_hash = HMAC-SHA256(key, encode("kchat-storage/node-key-commit/v1", tenant, node_id,
                                   u64(generation)))
```

```text
propose_root_key(root)               ──► KeyProposal { epoch, key_hash }, pending
  host: server CreateRootKey (epoch 0) / RotateRootKey(epoch, key_hash)
    won:  activate_node_key(key) ──► build_root_key_distribution(root, epoch, None)  to the group
    lost: discard_node_key(key); the winner's key arrives through process_control
build_root_key_bundle(root, member)  ──► newest active epochs (up to 4096) in one message,
                                         for a new member; older ones via key sync
build_key_sync_request(root, epochs, to) ──► KeySyncRequest (no key inside), when KeySyncRequired
process_control(request)             ──► KeySyncRequested(request); nothing is stored
build_key_sync_response(&request, authority) ──► NodeKeyDistribution for the requesting device,
                                         only epochs it holds and authority allows one by one
create_file_key(root, file_node)     ──► NewFileKey (pending) + NodeLink; activate once stored
open_file_key(link)                  ──► unwrap with the root key of the link's epoch, store
```

Personal roots are only ever sent to, and accepted from, the store's own account. A file node stays
under one root. Sealing or resealing with a File NodeKey wrapped under an older root epoch, or older
than the newest File NodeKey of the file on the device, is refused (`PolicyViolation`).

## Descriptor

KFiles stores one `EncryptedDescriptor` per READY blob (`profile_id`, `ciphertext`,
`file_epoch`); the SDK produces and opens it.

```text
ciphertext = record(File NodeKey, CBOR, encode("kchat-storage/descriptor/v2",
                    tenant, file_id, file_node_id, u64(file_gen), profile_id))
profile_id = "kchat-storage/descriptor/v2"   (EncryptedDescriptor.profile_id)
file_gen   = EncryptedDescriptor.file_epoch

CBOR = { "v": 1, "obj", "profile", "kg"?, "pg"?, "dek": bytes(32), "prefix": bytes(19),
         "psize", "csize", "csha": bytes(32), "app"?: bytes }           at most 1 MiB
```

```text
seal_descriptor(file_key, file_id, blob_id, object_id, key, app) ──► EncryptedDescriptor
open_descriptor(tenant, file_id, descriptor)  ──► OpenedBlob { object_id, content_key, app_manifest }
open_content(opened.content_key(), source, sink)
reseal_descriptor(file_id, blob_id, descriptor, new_file_key) ──► EncryptedDescriptor
```

`app` is an optional application manifest: opaque bytes the SDK encrypts with the descriptor but
never reads (`None` when there is none; an empty `Some` is rejected). The whole plaintext is capped at
`MAX_DESCRIPTOR_BYTES` (1 MiB), the KFiles limit.

The host rebuilds a descriptor from the server with `EncryptedDescriptor::from_parts(profile_id,
file_node_id, file_epoch, ciphertext)`; `file_node_id` is the lane's file key (`file_id` for the
GROUP lane, `<file_id>:user:<jid>` for a PRIVATE lane). `blob_id` is not in the AAD: on
`PublishFile` the server gives the GROUP blob its id only after the client sealed it. The object id
inside the descriptor ties it to one object; the host compares it with the object it downloads when
it knows that id.

`reseal_descriptor` decrypts with the old File NodeKey and encrypts the same plaintext with another
one: when a commit fails with `FILE_EPOCH_MISMATCH`, and when publishing a PRIVATE blob to the
group (the new key is the group file key, `blob_id` is the `draft_blob_id`). The object is not uploaded
again; the ciphertext changes.

Sealing is idempotent per `(tenant, file_id, blob_id)`: the same request (manifest included) returns
the stored ciphertext, a different one is an `OperationConflict`.

## Key store

- Dedicated SQLCipher database, never shared with MLS storage. The host supplies a 32-byte key,
  applied as a raw SQLCipher key; the SDK neither derives nor stores it.
- Opening refuses builds without SQLCipher (no plaintext store is ever created), a wrong key or a
  plaintext file (`InvalidStoreKey`), and a store bound to another account (`AccountMismatch`).
- Tables: `meta` (schema version, account id), `peppers`, `kkey_keys`, `kkey_policies`,
  `kkey_floors` (rollback floor per root), `prepared_ops`, `processed_events`, `node_keys`, `encrypted_descriptors`. Migrations only move forward. Each write is one transaction;
  `secure_delete` is on.

## Content profiles

```text
kchat-file/whole-file/xchacha-stream-64k/hybrid-voprf/v1
  oprf_out = VOPRF(k_T[key_gen], SHA-256(P))          RFC 9497, mode 0x01, ristretto255-SHA512
  PRK      = HKDF-Extract-SHA256(salt = "kchat-storage/hybrid-voprf/v1",
                                 IKM  = oprf_out || pepper || SHA-256(P))    64 + 32 + 32 bytes
  DEK      = HKDF-Expand(PRK, "kchat-file/whole-file/xchacha-stream/hybrid-voprf/key/v1", 32)
  prefix   = HKDF-Expand(PRK, "kchat-file/whole-file/xchacha-stream/hybrid-voprf/nonce-prefix/v1", 19)
  AAD      = encode("kchat-file/whole-file/xchacha-stream/hybrid-voprf/v1",
                    u64(key_gen), u64(pepper_gen), u64(len(P)))

kchat-file/whole-file/xchacha-stream-64k/random-dek/v1
  DEK, prefix = CSPRNG
  AAD         = encode("kchat-file/whole-file/xchacha-stream/random-dek/v1", u64(len(P)))
```

Both profiles use XChaCha20-Poly1305 STREAM-BE32 with 64 KiB plaintext blocks:

```text
nonce_i = prefix (19) || u32-be(i) || last_flag (1)
object  = block_0 || ... || block_last                 no header, no length prefix
csize(n) = 16 if n = 0, else n + 16 * ceil(n / 65536)  at most 5 GiB
```

A non-zero multiple of the block size ends with a full last block; an empty plaintext is a single
empty last block.

## Encoding

```text
encode(label, fields...) = lp(label) || field_1 || ...
  lp(bytes) = u32-be(len) || bytes      strings and byte strings
  u64-be(n)                             generations, versions and sizes
```

## Key-service trust

```text
public key: Ed25519(root, encode("kchat-storage/kkey-public-key/v1", tenant, u64(key_gen), pk_T))
policy:     Ed25519(root, encode("kchat-storage/kkey-policy/v1", tenant, u64(policy_version), policy))
policy      = "HYBRID" | "RANDOM"; unknown names are treated as "RANDOM"
pepper commitment = SHA-256("kchat-storage/pepper-commit/v1" || pepper)
```

Signatures are verified strictly against the single root the store was opened with (`None`: every
signature is rejected and only random plans are possible). Generations and policy versions never
move backwards; a hybrid plan is only created under a verified `HYBRID` policy, using the highest
verified key generation.

The host passes the root on every open, and the stored public keys and policies are re-verified
against it. Rows that no longer verify (signed by another root, or opened without a root) are deleted
and must be fetched again. The rollback floor is kept per root (`kkey_floors`): a new root starts from
its own floor, and reopening with an earlier root, even after an open without one, still rejects that
root's older generations and versions.

## Tests

All tests live in `tests/` and use only the public API.

- RFC 9497 Appendix A.1.2 vectors (batch sizes 1 and 2) for the pinned `voprf` release the client
  wraps.
- An in-test key service covers proof, signature, rollback (including per-root floors kept across
  opens with another root or none), policy and batch-size failures, and fresh blinds per session.
- Content tests cover canonical block boundaries, short reads, source changes and tampering.
- Key-store tests cover restarts, wrong keys and accounts, plaintext files, the pepper lifecycle,
  plan immutability per operation, stores written by a newer SDK, and that no pepper, tenant or schema text
  appears on disk.
- Key-tree tests cover epochs starting at 0, upload on one device and reading on a new member's
  device, rotation (old blobs stay readable, new blobs need the new epoch), bundles, lost rotation CAS,
  personal roots, swapped or tampered records, a wrong `file_epoch`, idempotent sealing, the app
  manifest (large, missing, conflicting, kept on reseal), descriptor reseal after an epoch change and
  on publish, reseal refused under a stale file key, links bound to every field, fresh nonces per
  record, an independent `key_hash` computation, and that no root key reaches the disk in clear.
- Control-message tests cover two devices exchanging bytes, once-only processing across restarts,
  recipient, authority and commitment checks, a hand-built message following the documented
  layout, inconsistent root-key messages, and malformed, truncated or bit-flipped input.
