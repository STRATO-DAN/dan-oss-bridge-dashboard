#!/usr/bin/env node
// [DAN] BRIDGE DASHBOARD — CLI entry.
//   (no args)                        start the local hub (loopback only), open the browser
//   register <id> --scope <cap> …    mint a principal: a connection token + an Ed25519 signing keypair
//                                    (control plane — the running hub exposes NO identity-minting route)
//   sign --principal <id> …          produce a signed message body ready to POST (private key from a file)
import { listen } from "../src/server.js";
import { AuthStore, newToken, normalizeScopes } from "../src/auth.js";
import { canonicalMessage, signMessage } from "../src/sign.js";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const cwd = process.cwd();
const dataDir = process.env.DAN_OSS_BRIDGE_DASHBOARD_DATA || path.join(cwd, ".dan-oss-bridge-dashboard");
const [, , cmd, ...rest] = process.argv;

function opts(argv) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith("--")) {
      const key = argv[i].slice(2);
      if (key === "scope") { (flags.scope ||= []).push(argv[++i]); }
      else flags[key] = argv[++i];
    } else positional.push(argv[i]);
  }
  return { flags, positional };
}

if (cmd === "register") {
  const { flags, positional } = opts(rest);
  const id = positional[0];
  if (!id) {
    console.error("usage: dan-oss-bridge-dashboard register <principalId> --scope channel:* [--scope channel:general] [--token <token>]");
    console.error("scopes: channel:<name> (post+read that channel), channel:* (all channels), admin");
    process.exit(1);
  }
  const normalized = normalizeScopes(flags.scope);
  if (normalized.length === 0) {
    console.error("at least one valid --scope is required (e.g. --scope channel:* or --scope channel:general or --scope admin)");
    process.exit(1);
  }
  const secret = flags.token || newToken();
  let reg;
  try {
    reg = await new AuthStore(dataDir).register(id, secret, normalized);
  } catch (err) {
    console.error(`register failed: ${err.message}`);
    process.exit(1);
  }
  const keyJson = JSON.stringify(reg.privateKey);
  console.log(`registered principal: ${id}`);
  console.log(`scopes:               ${normalized.join(", ")}`);
  console.log(`data dir:             ${dataDir}`);
  console.log(`\nconnection token (shown once — store it securely):\n\n  ${secret}\n`);
  console.log(`private signing key (shown once — save it to a file, e.g. ${id}.key.jwk):\n\n  ${keyJson}\n`);
  console.log(`post a signed message:`);
  console.log(`  echo '${keyJson}' > ${id}.key.jwk`);
  console.log(`  BODY=$(dan-oss-bridge-dashboard sign --principal ${id} --channel general --text "hello" --key-file ${id}.key.jwk)`);
  console.log(`  curl -H "X-Bridge-Principal: ${id}" -H "X-Bridge-Token: ${secret}" \\`);
  console.log(`    -H "content-type: application/json" -d "$BODY" \\`);
  console.log(`    http://127.0.0.1:4875/api/channels/general/messages`);
  process.exit(0);
}

if (cmd === "sign") {
  // Build and sign a message body. The private key is read from a FILE (never an argv flag), so the
  // secret never lands in the process list.
  const { flags } = opts(rest);
  const principal = flags.principal;
  const channel = flags.channel;
  const text = flags.text;
  const keyFile = flags["key-file"];
  if (!principal || !channel || text === undefined || !keyFile) {
    console.error('usage: dan-oss-bridge-dashboard sign --principal <id> --channel <name> --text "<text>" --key-file <path> [--nonce <n>] [--ts <ms>]');
    process.exit(1);
  }
  let privateKey;
  try {
    privateKey = JSON.parse(fs.readFileSync(keyFile, "utf8"));
  } catch (err) {
    console.error(`could not read private key from ${keyFile}: ${err.message}`);
    process.exit(1);
  }
  const nonce = flags.nonce || randomUUID();
  const ts = flags.ts !== undefined ? Number(flags.ts) : Date.now();
  let sig;
  try {
    sig = signMessage(privateKey, canonicalMessage({ from: principal, channel, nonce, ts, text }));
  } catch (err) {
    console.error(`signing failed: ${err.message}`);
    process.exit(1);
  }
  process.stdout.write(JSON.stringify({ text, nonce, ts, sig }) + "\n");
  process.exit(0);
}

// ── no-arg launcher path: hand-rolled flags (no dependency) ───────────────────────────────────────
// Reached only when the command is neither `register` nor `sign` (both exit above). These flags are
// additive: they never touch register/sign, and the human startup banner below is unchanged.
const launcherArgv = process.argv.slice(2);
const hasFlag = (f) => launcherArgv.includes(f);

if (hasFlag("--version")) {
  const pkg = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  console.log(pkg.version);
  process.exit(0);
}

if (hasFlag("--help")) {
  console.log(`[DAN] BRIDGE DASHBOARD — a local, loopback-only messaging hub for agents and scripts.

Usage:
  dan-oss-bridge-dashboard [options]
      Start the hub on 127.0.0.1 (loopback only) and open the UI in a browser.
  dan-oss-bridge-dashboard register <id> --scope <cap> [--scope <cap> …] [--token <token>]
      Mint a principal: a connection token + an Ed25519 signing keypair. Control plane only —
      the running hub exposes NO identity-minting route. Scopes: channel:<name>, channel:*, admin.
  dan-oss-bridge-dashboard sign --principal <id> --channel <name> --text "<text>" --key-file <path> [--nonce <n>] [--ts <ms>]
      Produce a signed message body (JSON) ready to POST. The private key is read from a FILE, so
      the secret never lands in the process list. Prints the body to stdout.

Launcher options:
  --help        Show this help and exit.
  --version     Print the version and exit.
  --json        Print the startup banner as ONE JSON object {"url","port"} instead of human text
                (for scripts / CI). In this mode the hub does not open a browser.

Environment:
  DAN_OSS_BRIDGE_DASHBOARD_PORT   Port to bind on 127.0.0.1 (default 4875; 0 = pick a free port).
  DAN_OSS_BRIDGE_DASHBOARD_DATA   Data directory (default ./.dan-oss-bridge-dashboard).

Exit codes:
  0   Success (including --help / --version).
  1   Runtime failure — e.g. the port is already in use, or a register / sign error.
  2   Launcher usage error — an unrecognized option was passed to the no-arg launcher.

The hub binds 127.0.0.1 only. Every API call is authenticated; until you register a principal the
API denies everything (fail-closed).`);
  process.exit(0);
}

// Any unrecognized --flag on the launcher path is a usage error (exit 2). Positional arguments are
// left untouched so existing behavior is unchanged.
const knownLauncherFlags = new Set(["--json"]);
const badFlag = launcherArgv.find((a) => a.startsWith("--") && !knownLauncherFlags.has(a));
if (badFlag) {
  console.error(`unknown option: ${badFlag}`);
  console.error("run `dan-oss-bridge-dashboard --help` for usage.");
  process.exit(2);
}

const jsonBanner = hasFlag("--json");

// Default port 4875; an explicit 0 means "pick a free ephemeral port" (handy for --json/CI). Any
// non-numeric or unset value falls back to the default, exactly as before.
const rawPort = process.env.DAN_OSS_BRIDGE_DASHBOARD_PORT;
const parsedPort = Number(rawPort);
const port = rawPort && Number.isInteger(parsedPort) && parsedPort >= 0 ? parsedPort : 4875;

let server;
try {
  server = await listen(port, dataDir);
} catch (err) {
  console.error(`[DAN] BRIDGE DASHBOARD could not start: ${err.message}`);
  process.exit(1);
}

const actualPort = server.address().port;
const url = `http://127.0.0.1:${actualPort}`;

if (jsonBanner) {
  process.stdout.write(JSON.stringify({ url, port: actualPort }) + "\n");
} else {
  console.log(`[DAN] BRIDGE DASHBOARD running at ${url}`);
  console.log("A real, local messaging gateway for agents — post, read, and watch shared channels.");
  console.log(`Channels saved to: ${dataDir}`);
  if (!server._bridge.auth.hasAnyPrincipal()) {
    console.log("\n⚠  No principals registered yet — every API call is denied until you mint one:");
    console.log("     dan-oss-bridge-dashboard register <id> --scope channel:*\n");
  }
  console.log("Ctrl-C to stop.\n");

  // execFile, not exec — no shell. On Windows `start` is a cmd builtin, so it runs via cmd.exe.
  // Human mode only: in --json (scripting/CI) mode we never spawn a browser.
  const [openerCmd, openerArgs] =
    process.platform === "darwin" ? ["open", [url]]
      : process.platform === "win32" ? ["cmd", ["/c", "start", "", url]]
        : ["xdg-open", [url]];
  execFile(openerCmd, openerArgs, () => {});
}

process.on("SIGINT", () => {
  server.close(() => process.exit(0));
});
