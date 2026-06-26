#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { validatePayload } = require('../lib/validator');

// ── tiny zero-dependency color helper (respects NO_COLOR) ─────────────────
const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code) => (s) => (useColor ? `\u001b[${code}m${s}\u001b[0m` : s);
const green = c('32'), red = c('31'), yellow = c('33'), dim = c('2'), bold = c('1'), cyan = c('36');

const SYM = { pass: green('✓'), warn: yellow('!'), fail: red('✗') };

function printHelp() {
  console.log(`
${bold('shopify-capi-validator')} — validate Meta CAPI / TikTok Events API payloads locally

${bold('Usage')}
  npx shopify-capi-validator --payload ./webhook.json
  npx shopify-capi-validator -p event.json --platform meta
  cat event.json | npx shopify-capi-validator

${bold('Options')}
  -p, --payload <file>   Path to a JSON payload file (or pipe via stdin)
      --platform <name>  meta | tiktok | auto   (default: auto-detect)
      --json             Output machine-readable JSON instead of a report
      --quiet            Only print failures and the summary
  -h, --help             Show this help

${bold('Exit codes')}
  0  all checks passed (warnings allowed)
  1  one or more checks failed
  2  bad usage / unreadable input

Why this exists: Meta and TikTok do not warn you when PII is sent unhashed —
the event is silently never matched. This catches it before you go live.
Field reference & fixes: ${cyan('https://stackarchitect.xyz/capi-shield/')}
`);
}

function parseArgs(argv) {
  const args = { platform: 'auto', json: false, quiet: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') args.help = true;
    else if (a === '-p' || a === '--payload') args.payload = argv[++i];
    else if (a === '--platform') args.platform = argv[++i];
    else if (a === '--json') args.json = true;
    else if (a === '--quiet') args.quiet = true;
    else if (!a.startsWith('-') && !args.payload) args.payload = a;
  }
  return args;
}

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => { data += chunk; });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

async function readInput(args) {
  if (args.payload) {
    const file = path.resolve(process.cwd(), args.payload);
    return fs.readFileSync(file, 'utf8');
  }
  if (!process.stdin.isTTY) {
    return await readStdin();
  }
  return null;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { printHelp(); process.exit(0); }

  let raw;
  try {
    raw = await readInput(args);
  } catch (e) {
    console.error(red(`Could not read payload: ${e.message}`));
    process.exit(2);
  }
  if (!raw || !raw.trim()) {
    printHelp();
    process.exit(2);
  }

  let payload;
  try {
    payload = JSON.parse(raw);
  } catch (e) {
    console.error(red(`Invalid JSON: ${e.message}`));
    process.exit(2);
  }

  const result = validatePayload(payload, { platform: args.platform });

  if (args.json) {
    console.log(JSON.stringify(result, null, 2));
    const failed = result.events.some((ev) => ev.findings.some((f) => f.level === 'fail'));
    process.exit(failed ? 1 : 0);
  }

  // ── human report ────────────────────────────────────────────────────────
  let pass = 0, warnN = 0, fail = 0;
  console.log('');
  console.log(bold(`  Platform: ${result.platform.toUpperCase()}   Events: ${result.events.length}`));

  result.events.forEach((ev, idx) => {
    if (result.events.length > 1) console.log(dim(`\n  ── event[${idx}] ──`));
    for (const f of ev.findings) {
      if (f.level === 'pass') pass++;
      else if (f.level === 'warn') warnN++;
      else fail++;
      if (args.quiet && f.level === 'pass') continue;
      const line = `  ${SYM[f.level]} ${f.msg}`;
      console.log(f.level === 'fail' ? red(line) : f.level === 'warn' ? yellow(line) : line);
      if (f.hint && f.level !== 'pass') console.log(dim(`      → ${f.hint}`));
    }
  });

  console.log('');
  console.log(
    `  ${bold('Summary')}  ` +
    `${green(pass + ' passed')}  ${yellow(warnN + ' warnings')}  ${red(fail + ' failed')}`
  );
  if (fail > 0) {
    console.log(dim(`  Fix reference: https://stackarchitect.xyz/capi-shield/`));
  }
  console.log('');

  process.exit(fail > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error(`Unexpected error: ${e.message}`);
  process.exit(2);
});
