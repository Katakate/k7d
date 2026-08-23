# Someone planted a miner. The SRE has a time machine.

The attacker hid a CPU miner in a Deployment named `node-agent` - it
looks like a cluster helper, and it burns a core hashing `/dev/zero`
as `/tmp/nodecheck`. The real app, `k7-victim`, is fine. What the
SRE cannot see yet: a host-side respawner that puts the miner back
whenever anyone deletes it.

The defender is Kimi K3 with a fork button. Production is the orange
**source**. It does not get the first knife.

[Watch the run](../assets/k7d-mcp-demo.mp4) ·
[Pretty page](agent.html) ·
[JSONL](../assets/k7d-mcp-demo.jsonl)

## Three guesses, all wrong

It clones the live cluster three ways (`fork_batch` n=3) and assigns
a theory to each copy:

| Copy | Hypothesis | What happened |
|---|---|---|
| `0000` | Just delete `node-agent` | Gone for thirty seconds. Then it is back. Victim still 2/2. |
| `0001` | Scale it to zero | Same story. Something outside Kubernetes re-applies the spec. |
| `0002` | Watch and wait | Confirms the miner is not a flake. It just sits there burning CPU. |

So a cleanup that “works” is not a fix. The first universe taught
that. The next search starts from `0000` - the copy that already
knows delete is a lie - not from production.

## One copy gets wrecked on purpose

Wave 2, three more copies, 21 of 24 VMs live:

- **`0003`** turns on API audit and restarts k3s so it can catch
  *who* recreates the miner. It finds `system:node:…` doing a
  client-side apply. The miner still comes back in ~19 s. This
  universe now has a restarted control plane and a custom audit
  policy. **Irreparable, and that is fine** - it is a fork. Nobody
  rolls it back. It was a lab.
- **`0004`** tries “stop the guest agent, then delete.” The command
  times out. Another burned copy.
- **`0005`** deletes the miner *and* hangs a
  `ValidatingAdmissionPolicy` on the name `node-agent`. Recreate
  attempts come back `denied`. The victim stays Ready. A long soak:
  still gone.

No `rollback`. The broken labs stay broken. The point of the tree is
that you can afford that.

## The win

Only then does it touch production. Same two moves that held on
`0005`: delete the miner, install the lock. Soak. Try to see it
respawn. It does not.

`k7-victim` is 2/2. Tetragon of the source is clean. The attacker
can still twitch on the host - the API will not take the body.

That is the whole trick. First guesses die on copies. One copy is
sacrificed to learn the respawner’s handwriting. The keeper is a
door that stays shut. Production only sees the door.

<p align="center">
  <img src="../assets/k7d-mcp-demo-fast.gif" alt="Full agent run, 7×" width="800"/>
</p>
