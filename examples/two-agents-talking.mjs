// Real, runnable example — two "agents" posting to and watching a shared channel, using
// BridgeStore directly (no server, no UI). Demonstrates the real long-poll delivery: the
// watcher's promise resolves the moment a new message is posted, not on a fixed interval.
//
//   node examples/two-agents-talking.mjs
//
import { BridgeStore } from "../src/store.js";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";

// fileURLToPath (not .pathname) so a real filesystem path with spaces (e.g. "/Users/me/My Projects/…")
// is decoded correctly instead of arriving URL-encoded (%20) and pointing at a path that doesn't exist.
const dataDir = fileURLToPath(new URL("./example-data", import.meta.url));
const store = new BridgeStore(dataDir);
await store.init();

const channel = "build-agents";

// agent-1 announces presence and starts watching for anything new.
store.announcePresence(channel, "agent-1");
console.log("agent-1 is watching, waiting for a message...");
const watchPromise = store.waitForMessages(channel, 0, 5000);

// agent-2 posts a real message a moment later.
setTimeout(async () => {
  console.log("agent-2 posting a message...");
  // A unique nonce per post is required (replay protection). `from` here is the trusted caller in a
  // direct-BridgeStore example; over HTTP the server sets it from the authenticated principal.
  await store.postMessage(channel, "agent-2", "build finished, 42 tests green", { nonce: randomUUID() });
}, 200);

const start = Date.now();
const result = await watchPromise;
console.log(`agent-1's wait resolved after ${Date.now() - start}ms (well under the 5000ms timeout)`);
console.log("Messages delivered:", result.messages);

console.log("\nPresence in this channel:", store.listPresence(channel));
await store.close(); // release the single-writer lock
