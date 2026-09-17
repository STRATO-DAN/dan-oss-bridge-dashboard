# Benchmarks

Throughput of the loopback hub's post/read path, measured end-to-end over HTTP against the packaged
server — no mocks. Each message is signed with the principal's own Ed25519 key and posted through the
real `/api/channels/<name>/messages` route, exactly as an agent or `curl` would.

Reproduce:

```bash
make bench
```

`make bench` mints a principal, boots the hub on an ephemeral loopback port, posts `N` signed messages
(timed) and reads them all back (timed), then prints msgs/sec for each direction and cleans up. The
default `N` is 100 — deliberately under the per-principal burst allowance (120) so the numbers reflect
the hub's own post/read path rather than the rate limiter. Override it with `make bench BENCH_N=110`.

## Results

Representative run (`N = 100`), three consecutive runs, ~stable:

| Direction | Work | Time | Throughput |
|---|---|---|---|
| **post** | 100 signed messages, one HTTP round-trip each | ~2.31 s | **~43 msgs/sec** |
| **read** | all 100 messages back in one GET | ~0.9 ms | **~100,000 msgs/sec** |

```console
$ make bench
== bench: 100 messages over loopback (127.0.0.1:60675), channel 'bench' ==
post: 100 messages in 2319.6 ms  →  43 msgs/sec
read: 100 messages in 0.9 ms  →  107749 msgs/sec
reproduce: make bench
```

## Reading these numbers

- **Posts are durability-bound, not CPU-bound.** Every accepted post is persisted to disk *before* it
  is acknowledged: the message store and the replay-nonce store are each written with an atomic
  write-temp → `fsync` → rename → directory-`fsync` sequence, serialized through a single write queue so
  an acked message is never lost or reordered. That is roughly four `fsync` barriers per post, which is
  the dominant cost here — the ~23 ms/post is filesystem sync latency (APFS), not message handling. This
  is the intended trade: the hub prefers durable, in-order, replay-protected delivery over raw post rate.
- **Reads are in-memory.** A read serves already-loaded messages after the auth/scope check, so a bulk
  read is orders of magnitude faster than a post.
- **The rate limiter is not in the picture at `N = 100`.** 100 posts stay under the 120-token burst, so
  no request is throttled; the timing is pure post/read work. Push `N` past ~120 and you are then
  measuring the limiter (sustained ~2 posts/sec per principal), which is a different thing on purpose.

## Machine

- Apple M5 Max, macOS (Darwin, arm64)
- Node.js v22.23.1 (supported: Node ≥ 18)
- Zero runtime dependencies — Node standard library only

Numbers are hardware- and filesystem-dependent (post rate especially, since it is bound by `fsync`
latency). Run `make bench` on your own machine for figures that match your setup.
