#!/usr/bin/env node

/**
 * Universal version bump script
 * Usage: node scripts/version.js --type=<alpha|patch|minor|major>
 */

const { execSync } = require("child_process");
const { ArgumentParser } = require("argparse");
const { default: chalk } = require("chalk");

// Validation configuration
const validTypes = ["alpha", "patch", "minor", "major"];

// Parse command line arguments
const parser = new ArgumentParser({
  description: "Universal version bump script",
});
parser.add_argument("--type", {
  choices: validTypes,
  default: "alpha",
  help: "Version bump type (alpha, patch, minor, major)",
});

const args = parser.parse_args();
const type = args.type;

async function main() {
  try {
    // Validate input upfront
    if (!validTypes.includes(type)) {
      throw new Error(
        'Invalid version type "' +
          type +
          '" - must be one of: ' +
          validTypes.join(", "),
      );
    }

    console.log(
      chalk.blue(
        "🔖 Bumping " +
          type +
          " version with changelog generation and git commit",
      ),
    );
    console.log("");

    // Step 1: Bump version with npm
    console.log(
      chalk.cyan(
        "📝 Step 1/3: Updating package.json version number (" + type + ")",
      ),
    );

    let versionCommand = "";
    if (type === "alpha") {
      versionCommand = "npm version prerelease --preid=alpha";
    } else {
      versionCommand = "npm version " + type;
    }

    execSync(versionCommand, { stdio: "inherit" });
    console.log(chalk.green("✅ Version number updated in package.json\n"));

    // Step 2: Generate changelog (currently placeholder)
    console.log(chalk.cyan("📋 Step 2/3: Generating changelog entries"));
    execSync('echo "Changelog generation skipped"', { stdio: "inherit" });
    console.log(
      chalk.yellow(
        "⚠️  Changelog generation skipped - implement when needed\n",
      ),
    );

    // Step 3: Amend commit with all changes
    console.log(
      chalk.cyan("🔨 Step 3/3: Staging changes and amending git commit"),
    );
    execSync("git add -A", { stdio: "inherit" });
    execSync("git commit --amend --no-edit", { stdio: "inherit" });
    console.log(chalk.green("✅ Changes committed to git\n"));

    console.log("");
    console.log(
      chalk.green.bold(
        '✅ Version bump completed - ready to push with tags using "yarn run release"',
      ),
    );
  } catch (error) {
    console.log("");
    console.error(chalk.red.bold("❌ Version bump failed"));
    console.error(chalk.red("   Error: " + error.message));
    process.exit(1);
  }
}

// Execute async main
main().catch((err) => {
  console.error(chalk.red.bold("❌ Unexpected error during version bump"));
  console.error(err);
  process.exit(1);
});
