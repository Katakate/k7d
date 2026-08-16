#!/usr/bin/env bash
# Resolve SSH key and node connection details.
# Source this file, don't execute it:  source utils/ssh-setup.sh
#
# After sourcing, these variables are set:
#   SSH_PRIVKEY  - path to private key file
#   SSH_OPTS     - array of SSH options
#   NODE         - user@ip string
#   _SSH_TMPDIR  - unused here, kept so callers' cleanup traps are valid
set -euo pipefail

: "${K7_NODE_IP:?set K7_NODE_IP to your Linux/KVM build host}"
NODE="${K7_NODE_USER:-root}@${K7_NODE_IP}"
_SSH_TMPDIR=""

SSH_PRIVKEY="${K7_SSH_KEY_FILE:-$HOME/.ssh/id_ed25519}"
[[ -f "$SSH_PRIVKEY" ]] || {
    echo "SSH key not found: $SSH_PRIVKEY (set K7_SSH_KEY_FILE)" >&2
    exit 1
}

# ServerAlive*: without them a half-open TCP socket (node reboot, NAT
# timeout) leaves the local ssh client blocked forever on a connection
# whose remote side is already gone — no output, no exit code.
SSH_OPTS=(
    -o StrictHostKeyChecking=accept-new
    -o ConnectTimeout=30
    -o ServerAliveInterval=15
    -o ServerAliveCountMax=4
    -i "$SSH_PRIVKEY"
)
