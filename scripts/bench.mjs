// Post/read throughput micro-benchmark for the loopback hub. Driven by `make bench`, which mints a
// principal, boots the hub on an ephemeral port, and passes connection details in via the environment.
//
// Node standard library only. Messages are signed IN-PROCESS with the principal's own key (via the
// package's own src/sign.js) so the benchmark measures the hub's HTTP post/read path, not N process
// spawns of the `sign` subcommand. N is kept under the per-principal burst (120) so the number
// reflects raw throughput rather than the rate limiter kicking in.
import http from "node:http";
import fs from "node:fs";
import { randomUUID } from "node:crypto";
import { pathToFileURL } from "node:url";

const { canonicalMessage, signMessage } = await import(pathToFileURL(`${process.env.REPO}/src/sign.js`).href);

const PORT = Number(process.env.PORT);
const TOKEN = process.env.TOKEN;
const N = Number(process.env.N) || 100;
const PRINCIPAL = "bench-agent";
const CHANNEL = "bench";
const privateKey = JSON.parse(fs.readFileSync(process.env.KEY_FILE, "utf8"));

const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });

function request(method, path, body) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const req = http.request(
      {
        host: "127.0.0.1",
        port: PORT,
        method,
        path,
        agent,
        headers: {
          "X-Bridge-Principal": PRINCIPAL,
          "X-Bridge-Token": TOKEN,
          ...(data ? { "content-type": "application/json", "content-length": data.length } : {}),
        },
      },
      (res) => {
        let chunks = "";
        res.on("data", (c) => (chunks += c));
        res.on("end", () => resolve({ status: res.statusCode, body: chunks }));
      },
    );
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

function signedBody(text) {
  const nonce = randomUUID();
  const ts = Date.now();
  const sig = signMessage(privateKey, canonicalMessage({ from: PRINCIPAL, channel: CHANNEL, nonce, ts, text }));
  return { text, nonce, ts, sig };
}

// ── post N messages, timed ──────────────────────────────────────────────────────────────────────
const postStart = process.hrtime.bigint();
for (let i = 0; i < N; i++) {
  const res = await request("POST", `/api/channels/${CHANNEL}/messages`, signedBody(`bench message ${i}`));
  if (res.status !== 200) {
    console.error(`post ${i} failed: HTTP ${res.status} ${res.body}`);
    process.exit(1);
  }
}
const postMs = Number(process.hrtime.bigint() - postStart) / 1e6;

// ── read them all back, timed ─────────────────────────────────────────────────────────────────────
const readStart = process.hrtime.bigint();
const read = await request("GET", `/api/channels/${CHANNEL}/messages?sinceId=0`);
const readMs = Number(process.hrtime.bigint() - readStart) / 1e6;
if (read.status !== 200) {
  console.error(`read failed: HTTP ${read.status} ${read.body}`);
  process.exit(1);
}
const got = JSON.parse(read.body).messages.length;

const postRate = Math.round((N / postMs) * 1000);
const readRate = Math.round((got / readMs) * 1000);

console.log(`post: ${N} messages in ${postMs.toFixed(1)} ms  →  ${postRate} msgs/sec`);
console.log(`read: ${got} messages in ${readMs.toFixed(1)} ms  →  ${readRate} msgs/sec`);

agent.destroy();
