# Node.js binding for Rust MLS SDK

This crate provides bindings for the MLS Rust SDK using [NAPI-RS](https://napi.rs/).

## Multiple MLS ciphersuites

The SDK uses one libcrux crypto provider and can keep groups using classic,
XWing, and full-PQ ciphersuites in the same local storage. Use
`newWithCiphersuitePolicy(preferredCiphersuite, supportedCiphersuites)` to
enable more than one suite, then use `generateKeyPackagesFor` and
`createGroupWithCiphersuite` for a specific suite. Existing API methods remain
available and use the preferred suite.

Each KeyPackage belongs to one ciphersuite. A group keeps the suite selected at
creation; changing a client's preferred suite never changes existing groups.
Classic and XWing Welcomes carry an embedded ratchet tree. A full-PQ Welcome
requires the separately transported ratchet tree and must be processed with
`processWelcomeWithRatchetTree`.

## Prerequisites

- Install the latest `Rust`
- Install `Node.js@10.20+` which fully supports `Node-API` v6 (required by the `napi6` feature)
- Install `yarn@4.x` (the crate ships `yarn@4.9.1` via Corepack)
- Install `napi`

## Setup

1. **Project Structure**
Ensure your project has the following structure:
```
.
├── .cargo
│   └── config.toml
├── src
│   └── lib.rs
├── build.rs
├── Cargo.toml
├── index.d.ts
├── index.js
└── package.toml
```

- `Cargo.toml`: Configures the Rust crate and dependencies.
- `src/lib.rs`: Contains the Rust code.
- `index.d.ts`: Node.js bindings.

2. **Write Rust Code to be called from C API**

Decorate a normal rust function with `#[napi]`:
```rust
#[napi]
pub fn sum(a: u32, b: u32) -> u32 {
	a + b
}
```

> **NOTE:** For more information, visit [napi-rs](https://napi.rs/docs/concepts/exports).

3. **Build**

```bash
yarn build
```
