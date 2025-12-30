#!/usr/bin/env node

/**
 * Install script for napi-rs package
 * Automatically rebuilds native binary if not found for current platform
 */

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

const platform = os.platform();
const arch = os.arch();

// Map Node.js platform/arch to Rust targets
const platformMap = {
  win32: {
    x64: "x86_64-pc-windows-msvc",
    ia32: "x86_64-pc-windows-msvc",
  },
  darwin: {
    x64: "x86_64-apple-darwin",
    arm64: "aarch64-apple-darwin",
  },
  linux: {
    x64: "x86_64-unknown-linux-gnu",
    arm64: "aarch64-unknown-linux-gnu",
  },
};

function getBinaryPath() {
  // Check npm directory structure first (pre-built binaries)
  const npmDir = path.join(__dirname, "..", "npm");
  const platformDir = `${platform}-${arch === "x64" ? "x64" : arch}`;
  const binaryPath = path.join(npmDir, platformDir, "kchat-mls-napi.node");

  if (fs.existsSync(binaryPath)) {
    return binaryPath;
  }

  // Check root level .node file
  const rootBinary = path.join(__dirname, "..", "kchat-mls-napi.node");
  if (fs.existsSync(rootBinary)) {
    return rootBinary;
  }

  return null;
}

function shouldRebuild() {
  // Check if binary exists
  const binaryPath = getBinaryPath();
  if (binaryPath) {
    console.log(`✓ Native binary found at: ${binaryPath}`);
    return false;
  }

  // Check if we can require the module (it might work even without explicit binary check)
  try {
    require("../index.js");
    console.log("✓ Module can be loaded");
    return false;
  } catch (e) {
    if (
      e.code === "MODULE_NOT_FOUND" ||
      e.message.includes("Cannot find module") ||
      e.message.includes(".node")
    ) {
      console.log("⚠ Native binary not found, will rebuild...");
      return true;
    }
    // Other errors might be runtime errors, not missing binary
    console.log("⚠ Module load error (may need rebuild):", e.message);
    return true;
  }
}

function rebuild() {
  const rustTarget = platformMap[platform]?.[arch];

  if (!rustTarget) {
    console.error(`❌ Unsupported platform: ${platform}-${arch}`);
    console.error("Supported platforms:");
    Object.entries(platformMap).forEach(([plat, archs]) => {
      Object.keys(archs).forEach((a) => console.error(`  - ${plat}-${a}`));
    });
    process.exit(1);
  }

  // Try to find napi command
  let napiCmd = "napi";
  const napiCliPath = path.join(
    __dirname,
    "..",
    "node_modules",
    ".bin",
    "napi",
  );
  if (fs.existsSync(napiCliPath)) {
    napiCmd = napiCliPath;
  } else {
    // Try global napi or npx
    try {
      execSync("which napi", { stdio: "ignore" });
    } catch {
      // Try npx as fallback
      napiCmd = "npx @napi-rs/cli";
    }
  }

  console.log(
    `🔨 Building native binary for ${platform}-${arch} (${rustTarget})...`,
  );
  console.log(
    "⚠ This requires Rust and @napi-rs/cli. If build fails, install them first:",
  );
  console.log("   npm install -g @napi-rs/cli");
  console.log("   or: cargo install napi-cli");
  console.log("");

  try {
    execSync(`${napiCmd} build --target ${rustTarget} --release`, {
      stdio: "inherit",
      cwd: path.join(__dirname, ".."),
    });
    console.log("✅ Build completed successfully");
  } catch (error) {
    console.error("❌ Build failed:", error.message);
    console.error("");
    console.error("To build manually, you need:");
    console.error("  1. Rust toolchain: https://rustup.rs/");
    console.error("  2. @napi-rs/cli: npm install -g @napi-rs/cli");
    console.error(
      "  3. Then run: napi build --target " + rustTarget + " --release",
    );
    console.error("");
    console.error(
      "Alternatively, if this package should have pre-built binaries,",
    );
    console.error("please report this issue to the package maintainer.");
    process.exit(1);
  }
}

// Main
if (shouldRebuild()) {
  rebuild();
} else {
  console.log("✓ Installation complete - no rebuild needed");
}
