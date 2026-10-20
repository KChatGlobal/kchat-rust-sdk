#!/usr/bin/env node

/**
 * Install script for napi-rs package.
 * Rebuild the native binary in a source checkout when no loadable binary exists.
 */

const { spawnSync } = require('node:child_process')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

const platform = os.platform()
const arch = os.arch()
const root = path.join(__dirname, '..')

// Match the MLS install script's supported targets.
const platformMap = {
  win32: { x64: 'x86_64-pc-windows-msvc' },
  darwin: { x64: 'x86_64-apple-darwin', arm64: 'aarch64-apple-darwin' },
  linux: { x64: 'x86_64-unknown-linux-gnu' },
}

function canLoadBinding() {
  if (!fs.existsSync(path.join(root, 'index.js'))) return false
  try {
    require('../index.js')
    return true
  } catch (error) {
    const missingBinding = error.code === 'MODULE_NOT_FOUND' ||
      String(error.message).startsWith('Cannot find native binding') ||
      String(error.message).startsWith('Failed to load native binding')
    if (!missingBinding) throw error
    return false
  }
}

function shouldRebuild() {
  if (canLoadBinding()) {
    console.log('Module can be loaded')
    return false
  }
  console.log('Native binary not found; building from source')
  return true
}

function rebuild() {
  const rustTarget = platformMap[platform]?.[arch]
  if (!rustTarget) throw new Error(`Unsupported platform: ${platform}-${arch}`)

  // Published packages contain binaries, not the Rust workspace needed to rebuild.
  if (!fs.existsSync(path.join(root, 'src', 'lib.rs')) ||
      !fs.existsSync(path.resolve(root, '../..', 'Cargo.toml'))) {
    throw new Error(`Native binary for ${platform}-${arch} is missing from this package`)
  }

  let cli
  try {
    cli = path.join(path.dirname(require.resolve('@napi-rs/cli/package.json')), 'dist', 'cli.js')
  } catch {
    throw new Error('Install @napi-rs/cli before building the native binary from source')
  }

  console.log(`Building native binary for ${platform}-${arch} (${rustTarget})`)
  const result = spawnSync(process.execPath, [cli, 'build', '--platform', '--release'], {
    stdio: 'inherit',
    cwd: root,
  })
  if (result.error) throw result.error
  if (result.status !== 0) process.exit(result.status || 1)
  if (!canLoadBinding()) throw new Error('NAPI build completed without a loadable native binary')
}

if (shouldRebuild()) {
  rebuild()
} else {
  console.log('Installation complete; no rebuild needed')
}
