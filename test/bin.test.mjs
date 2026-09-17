// Launcher-CLI regression tests: drive the REAL bin (bin/dan-oss-bridge-dashboard.js) as a child
// process and assert its exact stdout / stderr / exit codes for the no-arg launcher flags added in
// 0.4.0 (--version / --help / --json / unknown-flag / port-in-use). No mocks, no new deps: only the
// Node built-in test runner, node:assert/strict, and node:child_process. register/sign are covered
// elsewhere and are intentionally not exercised here. Every spawn points DAN_OSS_BRIDGE_DASHBOARD_DATA
// at a throwaway temp dir so the real data dir is never touched.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync, spawn } from "node:child_process";
import net from "node:net";
import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const BIN = fileURLToPath(new URL("../bin/dan-oss-bridge-dashboard.js", import.meta.url));
const PKG = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"));

async function tmpDataDir() {
  return fsp.mkdtemp(path.join(os.tmpdir(), "dan-oss-bridge-bin-"));
}

// Run the bin to completion (for the flags that exit immediately).
function runBin(args, extraEnv = {}) {
  return spawnSync(process.execPath, [BIN, ...args], {
    encoding: "utf8",
    env: { ...process.env, ...extraEnv },
  });
}

test("--version prints exactly the package version and exits 0", async () => {
  const dataDir = await tmpDataDir();
  try {
    const r = runBin(["--version"], { DAN_OSS_BRIDGE_DASHBOARD_DATA: dataDir });
    assert.equal(r.status, 0);
    assert.equal(r.stdout.trim(), PKG.version);
    assert.equal(r.stderr, "");
  } finally {
    await fsp.rm(dataDir, { recursive: true, force: true });
  }
});

test("--help prints usage (register/sign subcommands + exit codes) and exits 0", async () => {
  const dataDir = await tmpDataDir();
  try {
    const r = runBin(["--help"], { DAN_OSS_BRIDGE_DASHBOARD_DATA: dataDir });
    assert.equal(r.status, 0);
    assert.equal(r.stderr, "");
    const out = r.stdout;
    assert.match(out, /Usage:/);
    assert.match(out, /register <id> --scope/, "help documents the register subcommand");
    assert.match(out, /sign --principal/, "help documents the sign subcommand");
    assert.match(out, /--version/);
    assert.match(out, /--json/);
    // The exit-code legend must be present with all three codes.
    assert.match(out, /Exit codes:/);
    assert.match(out, /\b0\b/);
    assert.match(out, /\b1\b/);
    assert.match(out, /\b2\b/);
  } finally {
    await fsp.rm(dataDir, { recursive: true, force: true });
  }
});

test("an unknown launcher flag exits 2 with a usage error on stderr", async () => {
  const dataDir = await tmpDataDir();
  try {
    const r = runBin(["--nope"], { DAN_OSS_BRIDGE_DASHBOARD_DATA: dataDir });
    assert.equal(r.status, 2);
    assert.match(r.stderr, /unknown option: --nope/);
    assert.match(r.stderr, /--help/, "points the user at --help");
    assert.equal(r.stdout, "", "nothing is written to stdout on a usage error");
  } finally {
    await fsp.rm(dataDir, { recursive: true, force: true });
  }
});

test("--json with PORT=0 prints exactly one {url,port} object on the real bound port", async () => {
  const dataDir = await tmpDataDir();
  const child = spawn(process.execPath, [BIN, "--json"], {
    env: {
      ...process.env,
      DAN_OSS_BRIDGE_DASHBOARD_PORT: "0",
      DAN_OSS_BRIDGE_DASHBOARD_DATA: dataDir,
    },
  });

  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (d) => { stderr += d; });

  try {
    const banner = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("timed out waiting for JSON banner")), 10000);
      child.on("error", reject);
      child.on("exit", (code) => reject(new Error(`launcher exited early (code ${code}); stderr: ${stderr}`)));
      child.stdout.on("data", (d) => {
        stdout += d;
        if (stdout.includes("\n")) {
          clearTimeout(timer);
          resolve(stdout.slice(0, stdout.indexOf("\n")));
        }
      });
    });

    // Exactly one JSON object, nothing else on stdout.
    assert.equal(stdout.trim(), banner.trim(), "stdout is a single line — no banner text, no browser noise");
    const parsed = JSON.parse(banner);
    assert.deepEqual(Object.keys(parsed).sort(), ["port", "url"]);
    assert.ok(Number.isInteger(parsed.port) && parsed.port > 0, "port is the real ephemeral port");
    assert.equal(parsed.url, `http://127.0.0.1:${parsed.port}`);
    assert.equal(stderr, "", "--json mode is silent on stderr");
  } finally {
    child.kill("SIGKILL");
    await new Promise((r) => child.on("exit", r));
    await fsp.rm(dataDir, { recursive: true, force: true });
  }
});

test("a port already in use exits 1 with a one-line error and no stack", async () => {
  const dataDir = await tmpDataDir();
  // Occupy a loopback port ourselves, then point the launcher at it.
  const blocker = net.createServer();
  const port = await new Promise((resolve, reject) => {
    blocker.once("error", reject);
    blocker.listen(0, "127.0.0.1", () => resolve(blocker.address().port));
  });
  try {
    const r = runBin([], {
      DAN_OSS_BRIDGE_DASHBOARD_PORT: String(port),
      DAN_OSS_BRIDGE_DASHBOARD_DATA: dataDir,
    });
    assert.equal(r.status, 1);
    assert.equal(r.stdout, "", "no partial startup banner");
    const err = r.stderr.trim();
    assert.match(err, /could not start/, "reports a clean startup failure");
    assert.equal(err.split("\n").length, 1, "the error is a single line");
    assert.doesNotMatch(err, /\bat\s+.+:\d+:\d+/, "no stack trace is leaked");
  } finally {
    await new Promise((r) => blocker.close(r));
    await fsp.rm(dataDir, { recursive: true, force: true });
  }
});
