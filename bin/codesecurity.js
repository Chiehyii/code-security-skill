#!/usr/bin/env node
'use strict';

/**
 * codesecurity CLI
 *
 * Usage:
 *   codesecurity init                        install for all AI tools
 *   codesecurity init --ai claude            Claude Code only
 *   codesecurity init --ai cursor            Cursor only
 *   codesecurity init --ai windsurf          Windsurf only
 *   codesecurity init --ai copilot           GitHub Copilot only
 *   codesecurity init --ai codex             OpenAI Codex only
 *   codesecurity init --ai claude cursor     multiple at once
 *   codesecurity init --force                overwrite existing files
 */

const { spawnSync } = require('child_process');
const path = require('path');
const fs   = require('fs');

const SCRIPT = path.join(__dirname, '..', 'scripts', 'install_skill.py');

function usage(exitCode) {
  console.log(`
  Usage: codesecurity <command> [options]

  Commands:
    init          Install the skill into the current project

  Options:
    --ai <tool>   AI tool(s) to install for:
                    claude   Claude Code
                    cursor   Cursor
                    copilot  GitHub Copilot
                    windsurf Windsurf
                    codex    OpenAI Codex
                    all      All tools (default)
    --force       Overwrite existing files / upgrade
    --help        Show this message

  Examples:
    codesecurity init
    codesecurity init --ai claude
    codesecurity init --ai cursor windsurf
    codesecurity init --force
`);
  process.exit(exitCode ?? 0);
}

// ── parse args ──────────────────────────────────────────────────────────────
const [, , command, ...rest] = process.argv;

if (!command || command === '--help' || command === '-h') {
  usage(command ? 0 : 1);
}

if (command !== 'init') {
  console.error(`Unknown command: "${command}"`);
  usage(1);
}

// Verify install script exists (guards against broken npm pack)
if (!fs.existsSync(SCRIPT)) {
  console.error(`Error: install script not found at ${SCRIPT}`);
  process.exit(1);
}

// ── run Python installer ─────────────────────────────────────────────────────
// Try python3 first, fall back to python
for (const python of ['python3', 'python']) {
  const result = spawnSync(python, [SCRIPT, '.', ...rest], { stdio: 'inherit' });

  if (result.error?.code === 'ENOENT') {
    continue; // not found, try next
  }

  if (result.error) {
    console.error(`Error running Python: ${result.error.message}`);
    process.exit(1);
  }

  process.exit(result.status ?? 0);
}

console.error(
  'Error: Python 3 is required but was not found.\n' +
  '  Install it from https://python.org and make sure it is on your PATH.'
);
process.exit(1);
