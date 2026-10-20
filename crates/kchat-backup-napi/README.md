# Node.js binding for Rust Backup SDK

This crate provides bindings for the KChat backup Rust SDK using [NAPI-RS](https://napi.rs/).

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
   │   ├── error.rs
   │   ├── io.rs
   │   └── lib.rs
   ├── build.rs
   ├── Cargo.toml
   ├── index.d.ts
   ├── index.js
   └── package.json
   ```

   - `Cargo.toml`: Configures the Rust crate and dependencies.
   - `src/lib.rs`: Exposes the backup key and descriptor APIs.
   - `src/io.rs`: Exposes the streaming encryption and decryption APIs.
   - `src/error.rs`: Converts Rust errors to Node.js errors.
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
