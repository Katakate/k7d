# k7d MCP - SRE with a time machine

stdio MCP server that wraps the k7d cluster-fork tree. A frontier
agent (Cursor CLI / Claude Code) diagnoses a live Ubuntu
Cilium+Tetragon incident by forking hypotheses, scoring Tetragon
diffs, protecting winners, and pruning losers under a real
`TreeBudget`.

k7d itself stays a Unix-socket daemon. This process is a node-local
sidecar .

## Tools

| Tool | Wraps |
|---|---|
| `tree_status` | `tree_list` + `tree_nodes` (usage + budget) |
| `fork_batch(node_id, n)` | `tree_fork_batch` |
| `branch_exec(node_id, member, cmd)` | guest-agent exec on one member |
| `tetragon_diff(node_id)` | Tetragon event-stream diff vs source |
| `protect` / `prune` / `rollback` | the tree verbs |

Every call appends one JSONL line (ts, tool, args, latency, usage).
`plots.py` reads that log.

## Cursor CLI

On the KVM node, after `scenario_incident.py` has printed a tree id
(or you brought one up yourself):

```bash
# pin the Ubuntu gym node from the environment - do not walk K7_NODE_IPS
export K7_NODE_IP="${K7_NODE_IP:?set K7_NODE_IP to the Ubuntu gym node}"
unset K7_NODE_IPS

# Ubuntu 24.04 is PEP 668 - use the node venv, not system pip
make k7d-mcp-deps
# or: python3 -m venv /var/lib/k7d/mcp-venv && /var/lib/k7d/mcp-venv/bin/pip install -r examples/k7d-mcp/requirements.txt
# edit mcp.cursor.json: K7D_TREE_ID + K7D_CERTS_DIR
cursor-agent --mcp-config examples/k7d-mcp/mcp.cursor.json \
  "$(cat examples/k7d-mcp/SYSTEM_PROMPT.md)"
```

`mcp.cursor.json` is the file to point Cursor CLI at.

## Claude Code

Same server, same env. Use `mcp.claude.json` as the project
`.mcp.json` (or merge the `mcpServers.k7d` block). stdio only - no
remote transport, no auth.

## Harness

```bash
# CI: everything but the model
python3 examples/k7d-mcp/scenario_incident.py --policy scripted --both-arms

# same incident, no forks (blast-radius baseline)
python3 examples/k7d-mcp/scenario_incident.py --policy scripted --no-fork

# frontier agent (needs cursor-agent + keys)
python3 examples/k7d-mcp/scenario_incident.py --policy cursor-agent --view http://127.0.0.1:7474

python3 examples/k7d-mcp/plots.py --dir examples/k7d-mcp/logs --out examples/k7d-mcp/plots
```

`--policy scripted` injects a catalog incident (`relay` by default - 
a miner Deployment plus a host-side systemd path-unit reseed the
pre-fork inspect battery cannot name. Also `sleeper` / `hydra` /
`cryptominer` / `lateral`), forks two hypotheses,
remediates on a fork, then replays on the source. Teardown always
`prune`+`drop`s the tree.

Guest is the 25a Ubuntu image via `gym/ubuntu.py`. Never
`K7D_KERNEL`/`K7D_INITRD` (those are the busybox RuntimeClass pair).

## Tests

`make gym-test` (and therefore `make remote-check`) runs:

- MCP round-trip against `gym/stub.py --k7d-socket` (every tool +
  error paths)
- one Ubuntu end-to-end smoke on the node: fork n=2, `branch_exec`,
  `tetragon_diff`, prune, zero residue
