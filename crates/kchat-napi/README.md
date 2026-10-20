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
