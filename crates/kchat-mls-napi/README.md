# Node.js binding for Rust MLS SDK

This crate provides bindings for the MLS Rust SDK using [NAPI-RS](https://napi.rs/).

## Prerequisites

- Install the latest `Rust`
- Install `Node.js@10+` which fully supported `Node-API`
- Install `yarn@1.x`
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
