# k7view - k7d-view

Live observer for k7d snapshot trees. Polls `/run/k7d/k7d.sock`, serves
a single-page dashboard on `http://127.0.0.1:7474`, fans updates out
over **one SSE stream** (`EventSource` / `text/event-stream`).

There is no Convex backend and no WebSocket. The browser uses **one
SSE stream** (`EventSource` / `/api/events`) at `--poll-ms 50` (k7d
`tree_list`/`tree_nodes` snapshots). A **vsock probe** thread pings live
guest agents and periodically `exec`s `/proc/uptime` + `/proc/loadavg`
(real RTT, real guest text). Tiles never invent rtt/dirty numbers.
OpenRouter, when configured, streams real tokens over those measurements.
Click-to-protect/evict is `POST /api/action`. k7d stays a unix-socket
JSON-lines daemon; this process joins `node_id` to notes, streamed
traces, and a controller/meta thread. Notes never go into `tree.json`.

OpenRouter is optional. `--profile max` streams canned text into the
tiles unless `OPENROUTER_API_KEY` is set (or `/root/.k7view-openrouter`
exists). Then each live branch and the controller thread stream a
fast model (`OPENROUTER_MODEL`, default `google/gemini-3.1-flash-lite`).
`--no-llm` forces the canned path. The key must not be committed.

`tree_nodes` / `tree_list` carry daemon `usage` + `budget` and live
guest CIDs; `tree_fork*` reports `latency_ns`. `dump_serial` finds tree
members by CID. Optional `tree_watch` streams mutations on one
control-socket connection.

Not a trainer. Not Claude Mythos.

## Run (on the KVM node)

Run on a Linux/KVM host with `k7d` listening on `/run/k7d/k7d.sock`.

```bash
# terminal 1
python3 examples/k7view/server.py --bind 127.0.0.1 --port 7474

# terminal 2 - quick smoke (4-branch, one cluster)
K7D_KERNEL=/usr/local/share/k7d/vmlinux \
K7D_INITRD=/usr/local/share/k7d/initramfs.cpio.gz \
python3 examples/k7view/run_scenario.py --keep --branches 4

# terminal 2 - video / max-load (multi-wave cluster tree + VM tree,
# tight VM budget so the bars go hot and auto-evict fires)
K7D_KERNEL=/usr/local/share/k7d/vmlinux \
K7D_INITRD=/usr/local/share/k7d/initramfs.cpio.gz \
python3 examples/k7view/run_scenario.py --profile max --keep
# equivalent:  python3 examples/k7view/run_scenario.py --video --keep

# terminal 2 - ×8 dilated Ubuntu k3s. Requires patched
# KVM modules (`make remote-dilation-install`). Never K7D_KERNEL/INITRD.
python3 examples/k7view/run_scenario.py --profile ubuntu-dilated --keep \
    --log /tmp/k7d-dilated-tree.jsonl
```

`--profile ubuntu-dilated` creates a 3-node Ubuntu k3s source through
`/run/k7d/k7d.sock` with `config.dilation = 8` (CreateVm × 3 + adopt,
same helpers as `gym/ubuntu.py`), then 3 waves (`6 + 4 + 4`) forking
from the previous winner. Each branch applies a Deployment whose
readiness gate is guest time (`initialDelaySeconds: 40`); under ×8
that is ~5–6 s of wall. Fork latency chips stay wall-clock. The
header shows wall `T+mm:ss` next to `guest T+mm:ss ×N` (uptime from
the existing vsock probe, N from `tree_nodes.live_dilation`). JSONL
records every fork latency, rollout wall/guest time, and
`live_dilation`.

`--profile max` default is 3 waves (`8 + 4 + 4` cluster forks of a
3-VM busybox cluster) plus a 6-branch single-VM tree. Wave 0 forks from
root (depth 1). Later waves call real `tree_prepare_fork_source` on the
winner, then `fork_batch` from that child (depth 2, then 3). k7d parent
ids are authentic - the UI does not invent edges. Wave 1 fills
~90% of `max_live_vms`; later waves park losers first (the RL policy of
killing branches - kept for protect-chain visibility). The daemon also
evicts for incoming VMs inside `fork_batch` (CHALLENGES #115), so
parking is no longer required for a legal under-budget fork.
The graph is generation-based so a
`fork_batch` fan-out does not stack on one x position.

Measured on a 12-core / 62 GiB box (2026-08-19), after
child `prepare_fork_source` landed - **k7d parent chains, not UI
fiction**:

- 3-VM root `tree_create_cluster` 2006 ms
- wave-0 `fork_batch` 8 from `root` in 353.1 ms (44.1 ms/branch) →
  `max_depth=1`
- `tree_prepare_fork_source` on the wave-0 winner: `wrote_base=True`
  in 797 ms (real 256 MiB snapshots)
- wave-1 `fork_batch` 4 from that child in 256.9 ms → `max_depth=2`
- prepare the wave-1 winner: `wrote_base=True` in 787 ms
- wave-2 `fork_batch` 4 from that grandchild in 294.9 ms →
  `max_depth=3`
- VM tree: prepare a child 274 ms, then 3 forks in 15.1 ms →
  `max_depth=2`

OpenRouter tiles/controller used `google/gemini-3.1-flash-lite` when
the key was present. Errors such as `node not found` on a second
suspend of an already-parked id are real k7d errors, not injected
copy.

From a laptop / cloud agent, tunnel then open the UI:

```bash
ssh -L 7474:127.0.0.1:7474 root@${K7_NODE_IP}
# http://127.0.0.1:7474/
```

## Live agent runs (MCP bridge)

`ingest_mcp.py` tails the `k7d-mcp` harness JSONL and posts cmd /
verdict / beat / latency / note events into `/api/ingest`, so a real
agent run renders live with zero changes to the harness or the MCP
server:

```bash
# on the node, next to server.py
python3 examples/k7view/ingest_mcp.py --dir examples/k7d-mcp/logs

# then run the incident (scripted or codex agent policy)
python3 examples/k7d-mcp/scenario_incident.py --policy cursor-agent \
    --incident lateral --view http://127.0.0.1:7474

# or re-render a finished run locally against gym/stub.py
python3 gym/stub.py --k7d-socket /tmp/k7d-stub.sock &
python3 examples/k7view/server.py --socket /tmp/k7d-stub.sock &
python3 examples/k7view/ingest_mcp.py --replay path/to/ep-fork-0-x.jsonl \
    --speed 4 --stub-socket /tmp/k7d-stub.sock
```

## Recording the demo video

Capture runs on any workstation that can reach the UI - the k7d node
needs nothing beyond the stdlib server. `capture.py` drives headless
Chrome over CDP at 1920x1080, waits for the run to reach the agent
phase, grabs PNG frames, and encodes with ffmpeg:

```bash
# deps on the capture box only: google-chrome, ffmpeg, pip install websockets
ssh -N -L 7475:127.0.0.1:7474 root@${K7_NODE_IP} &   # tunnel
python3 examples/k7view/capture.py --url http://127.0.0.1:7475/ \
    --out /tmp/take1 --fps 8 --start-phase agent --stop-phase idle
# /tmp/take1/capture.mp4 is real-time; the agent videos may speed the
# boring parts. The dilated-tree hero must NOT use setpts:
python3 examples/k7view/capture.py --url http://127.0.0.1:7475/ \
    --out /tmp/dilated --fps 8 --start-phase ready --stop-phase idle --max-s 90
# trim only (cut source bring-up if it leaked in; open on the Ready root).
# If CDP lagged, capture.mp4 encoded at --fps is a silent speed-up
# (CHALLENGES #203) — re-encode from frames at N/duration instead:
#   ffmpeg -framerate 181/90 -i /tmp/dilated/frames/f_%05d.png ...
ffmpeg -ss 0 -i /tmp/dilated/capture.mp4 -c copy -an docs/assets/k7d-dilated-tree.mp4
ffmpeg -ss 0 -t 14 -i docs/assets/k7d-dilated-tree.mp4 -vf \
  "fps=10,scale=960:-1:flags=lanczos,split[a][b];[a]palettegen[p];[b][p]paletteuse" \
  docs/assets/k7d-dilated-tree.gif
```

## Tests

```bash
python3 examples/k7view/test_store.py
python3 examples/k7view/test_probe.py
# or: make k7view-test
```
