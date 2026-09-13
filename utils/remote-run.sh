#!/usr/bin/env bash
# Run a long command on the bare-metal node, detached from the SSH
# connection that started it, and stream its output back.
#
# `ssh node "make check"` ties a 25-40 minute suite to a single TCP
# connection: when that connection drops the node-side `make` gets
# SIGHUP'd mid-suite and the local client is left with no exit code —
# just a log that stopped growing. Here the remote work runs under
# `nohup setsid` writing to a log on the node, and the SSH connection is
# only a viewer. Dropping it loses nothing: re-invoking the same target
# reattaches to the run in flight instead of starting a second one, and
# the local exit code is always the remote command's own.
#
# See CHALLENGES.md #64.
set -euo pipefail

usage() {
    cat >&2 <<'USAGE'
usage: utils/remote-run.sh <run-name> <remote-shell-command>

Rsyncs the workspace, then runs <remote-shell-command> in the node's
repo directory detached from this SSH connection, streaming its output.
Exits with the remote command's exit code.

If a run of the same name is still in flight, attaches to it and skips
the rsync (its sources are what that run is building).

A run of a *different* name on the same node waits: one workspace, one
run at a time.

  K7_REMOTE_RESTART=1     kill an in-flight run of this name, start fresh
  K7_REMOTE_LOCK_WAIT=n   seconds to wait for the workspace lock (default 2700)
USAGE
    exit 2
}

[[ $# -eq 2 ]] || usage
RUN_NAME="$1"
REMOTE_CMD="$2"
[[ "$RUN_NAME" =~ ^[a-z0-9][a-z0-9-]*$ ]] || {
    echo "invalid run name: $RUN_NAME" >&2
    exit 2
}

REPO_ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
cd "$REPO_ROOT"
source utils/ssh-setup.sh
cleanup() {
    kill_stale_viewers
    [[ -n "${_SSH_TMPDIR:-}" ]] && rm -rf "$_SSH_TMPDIR"
    return 0
}
trap cleanup EXIT

REMOTE_DIR="${K7_REMOTE_DIR:-/root/k7d}"
RUN_DIR="/run/k7d-remote/$RUN_NAME"
LOCK_FILE="/run/k7d-remote/workspace.lock"
LOCAL_LOG="$REPO_ROOT/.remote-runs/$RUN_NAME.log"
RECONNECT_LIMIT=10
RECONNECT_DELAY=5
LOCK_WAIT="${K7_REMOTE_LOCK_WAIT:-2700}"
LOCK_MAX_HOLD=21600  # 6h: a hung run must not own the node forever
LOCK_START_GRACE=180 # release if the run it was taken for never starts

mkdir -p "$(dirname "$LOCAL_LOG")"
# The reattach path never truncates/creates the local log (only start_run
# does), but `local_log_size` reads it via `<` — under `set -e` a missing
# file kills the viewer with a bare "No such file or directory" instead of
# reattaching from offset 0. Fresh checkouts reattaching to an in-flight
# run hit this (CHALLENGES #116).
[[ -f "$LOCAL_LOG" ]] || : >"$LOCAL_LOG"

node_sh() { ssh "${SSH_OPTS[@]}" "$NODE" "$@"; }

# The local viewer is a plain `ssh ... tail -f` piped into `tee -a`. If
# the process that owned it was SIGKILLed (a dying agent, a closed
# laptop), the ssh is orphaned and keeps appending to the local log —
# and since the log's size is what a reattach uses as its resume
# offset, a second viewer duplicates every line from there on. Reap any
# viewer of this run before attaching, and our own on the way out.
VIEWER_MARKER="k7d-remote-viewer=$RUN_NAME"

kill_stale_viewers() {
    local pid victims=()
    for pid in $(pgrep -f "$VIEWER_MARKER" 2>/dev/null || true); do
        # The marker can appear in any command line that merely mentions
        # it (a grep, a ps). Only ever signal an actual ssh client.
        [[ "$pid" == "$$" ]] && continue
        [[ "$(ps -o comm= -p "$pid" 2>/dev/null)" == ssh ]] && victims+=("$pid")
    done
    [[ ${#victims[@]} -eq 0 ]] && return 0
    echo "==> Reaping stale viewer(s) of '$RUN_NAME': ${victims[*]}" >&2
    kill "${victims[@]}" 2>/dev/null || true
    sleep 1
    return 0
}

local_log_size() { wc -c <"$LOCAL_LOG" 2>/dev/null | tr -d '[:space:]'; }

# done    = the run recorded an exit code
# running = the pid file names a live process
# none    = no run, or one that died without recording anything
run_state() {
    node_sh "
        if [ -f '$RUN_DIR/status' ]; then echo done
        elif [ -f '$RUN_DIR/pid' ] && kill -0 \"\$(cat '$RUN_DIR/pid')\" 2>/dev/null; then echo running
        else echo none; fi"
}

# One workspace on the node, one run at a time.
#
# Two agents rsyncing into and building in the same $REMOTE_DIR interleave:
# one overwrites sources the other is compiling, and the result looks like a
# flaky suite rather than like contention, so it gets retried instead of
# fixed. The ops-side node lease is advisory (a launched agent still reads
# K7_NODE_IP from its own environment), so the hard interlock has to live
# here, in the runner every agent already goes through.
#
# The lock is held by a detached node-side process, not by an ssh session,
# because an ssh drop must not release it mid-build. The kernel releases it
# if that process dies, so a killed agent cannot wedge the node.
acquire_workspace_lock() {
    node_sh "mkdir -p '$RUN_DIR' && rm -f '$RUN_DIR/lock.pid' '$RUN_DIR/lock.err' '$RUN_DIR/lock.launched'"
    # Write the holder to a file and launch that: a detached process cannot
    # be fed on stdin, because the `</dev/null` that detaches it from this
    # ssh connection is the same stdin the script would arrive on.
    node_sh "cat > '$RUN_DIR/hold.sh'" <<HOLD
#!/usr/bin/env bash
: > '$RUN_DIR/lock.launched'
exec 9>'$LOCK_FILE'
if ! flock -w $LOCK_WAIT 9; then
    echo timeout > '$RUN_DIR/lock.err'
    exit 75
fi
echo "$RUN_NAME pid \$\$ since \$(date -Is)" > '$LOCK_FILE.holder'
echo \$\$ > '$RUN_DIR/lock.pid'
started=\$(date +%s)
while [ ! -f '$RUN_DIR/status' ]; do
    elapsed=\$(( \$(date +%s) - started ))
    [ ! -f '$RUN_DIR/pid' ] && [ \$elapsed -gt $LOCK_START_GRACE ] && break
    [ \$elapsed -gt $LOCK_MAX_HOLD ] && break
    sleep 2
done
# flock is the truth; this file only names the holder in someone else's
# wait message, so a stale one would misattribute the wait.
rm -f '$LOCK_FILE.holder'
HOLD
    node_sh "cd / && nohup setsid --fork bash '$RUN_DIR/hold.sh' >/dev/null 2>&1 </dev/null"

    local waited=0 announced=0 holder=""
    while :; do
        if [[ "$(node_sh "cat '$RUN_DIR/lock.pid' 2>/dev/null || true")" =~ ^[0-9]+$ ]]; then
            return 0
        fi
        if [[ -n "$(node_sh "cat '$RUN_DIR/lock.err' 2>/dev/null || true")" ]]; then
            echo "==> Timed out after ${LOCK_WAIT}s waiting for the workspace lock on $NODE." >&2
            echo "==> Held by: $(node_sh "cat '$LOCK_FILE.holder' 2>/dev/null || echo unknown")" >&2
            return 75
        fi
        # "Holder never launched" and "lock is busy" look identical from here
        # unless the holder says it started. Without this marker a failed
        # launch waits out the whole timeout — silence pretending to be work.
        if ((waited >= 20)) && ! node_sh "test -f '$RUN_DIR/lock.launched'"; then
            echo "==> Lock holder for '$RUN_NAME' never started on $NODE." >&2
            return 75
        fi
        if ((announced == 0)); then
            announced=1
            holder="$(node_sh "cat '$LOCK_FILE.holder' 2>/dev/null || true")"
            echo "==> Waiting for the workspace lock on $NODE (held by: ${holder:-unknown})"
        fi
        waited=$((waited + 2))
        if ((waited > LOCK_WAIT + 30)); then
            echo "==> Gave up waiting for the workspace lock on $NODE." >&2
            return 75
        fi
        sleep 2
    done
}

release_workspace_lock() {
    local pid
    pid="$(node_sh "cat '$RUN_DIR/lock.pid' 2>/dev/null || true")" || return 0
    [[ "$pid" =~ ^[0-9]+$ ]] || return 0
    node_sh "kill '$pid' 2>/dev/null; true"
    node_sh "rm -f '$RUN_DIR/lock.pid'"
    return 0
}

start_run() {
    acquire_workspace_lock || return $?
    # Giving up before the run exists must hand the node back now. The
    # holder's start grace would do it eventually, but "eventually" is
    # minutes of another agent waiting on a lock nobody is using.
    if ! bash utils/rsync-to-node.sh; then
        release_workspace_lock
        return 1
    fi
    echo "==> Starting '$RUN_NAME' on $NODE: $REMOTE_CMD"
    node_sh "mkdir -p '$RUN_DIR' && cat > '$RUN_DIR/cmd.sh'" <<<"$REMOTE_CMD"
    # Stamp who dispatched this run so a job found on a node is always
    # attributable (host, agent id if any, user, time).
    node_sh "cat > '$RUN_DIR/origin'" <<<"host=$(hostname) agent=${CURSOR_CONVERSATION_ID:-none} user=$(whoami) at=$(date -Is)"
    # The wrapper records its own pid (setsid --fork means the starting
    # shell never sees it) and, from an EXIT trap, always records an
    # exit code — a run that dies without one is a failure we report
    # rather than a hang.
    node_sh "cat > '$RUN_DIR/run.sh'" <<WRAP
#!/usr/bin/env bash
finish() {
    rc=\$?
    echo "\$rc" > '$RUN_DIR/status.tmp'
    mv '$RUN_DIR/status.tmp' '$RUN_DIR/status'
}
trap finish EXIT
echo \$\$ > '$RUN_DIR/pid'
cd '$REMOTE_DIR' || exit 1
source \$HOME/.cargo/env 2>/dev/null || true
source \$HOME/.elan/env 2>/dev/null || true
export PATH="\$HOME/aeneas/bin:\$HOME/aeneas/charon/bin:\$PATH"
bash '$RUN_DIR/cmd.sh'
WRAP
    node_sh "cd '$RUN_DIR' && rm -f status pid && : > log && cd / && \
        nohup setsid --fork bash '$RUN_DIR/run.sh' >> '$RUN_DIR/log' 2>&1 </dev/null"
    : >"$LOCAL_LOG"

    local state
    for _ in $(seq 1 20); do
        state="$(run_state)" || state=unreachable
        [[ "$state" == none ]] || return 0
        sleep 1
    done
    echo "==> '$RUN_NAME' never came up on $NODE (no pid after 20s)" >&2
    release_workspace_lock
    return 1
}

# Follow the node-side log from wherever the local copy left off, until
# the remote command records an exit code. Survives dropped connections.
stream_run() {
    local failures=0 rc before after status
    while true; do
        before="$(local_log_size)"
        set +e
        ssh "${SSH_OPTS[@]}" "$NODE" "
            : $VIEWER_MARKER
            pid=\$(cat '$RUN_DIR/pid' 2>/dev/null) || exit 97
            [ -n \"\$pid\" ] || exit 97
            exec tail -c +$((before + 1)) -f --pid=\"\$pid\" '$RUN_DIR/log'" |
            tee -a "$LOCAL_LOG"
        rc=${PIPESTATUS[0]}
        set -e
        after="$(local_log_size)"
        if [[ "$after" != "$before" ]]; then failures=0; fi

        status="$(node_sh "cat '$RUN_DIR/status' 2>/dev/null || true")" || status=""
        if [[ -n "$status" ]]; then
            # `tail --pid` can exit before the last writes land.
            if ! node_sh "tail -c +$((after + 1)) '$RUN_DIR/log'" | tee -a "$LOCAL_LOG"; then
                echo "==> Could not read the tail of $RUN_DIR/log; exit code below is authoritative" >&2
            fi
            [[ "$status" =~ ^[0-9]+$ ]] || {
                echo "==> '$RUN_NAME' recorded a non-numeric exit code: $status" >&2
                return 1
            }
            echo "==> '$RUN_NAME' finished on $NODE with exit code $status"
            return "$status"
        fi

        local state
        state="$(run_state)" || state=unreachable
        if [[ "$state" == none ]]; then
            echo "==> '$RUN_NAME' died on $NODE without recording an exit code (viewer exit $rc)" >&2
            return 1
        fi

        failures=$((failures + 1))
        if ((failures > RECONNECT_LIMIT)); then
            echo "==> lost contact with $NODE $RECONNECT_LIMIT times in a row; giving up." >&2
            echo "==> The run may still be going: ssh $NODE tail -f $RUN_DIR/log" >&2
            return 1
        fi
        echo "==> Lost the connection to $NODE (viewer exit $rc, run is $state) —" \
            "reattaching in ${RECONNECT_DELAY}s ($failures/$RECONNECT_LIMIT)" >&2
        sleep "$RECONNECT_DELAY"
    done
}

on_interrupt() {
    echo >&2
    echo "==> Detached from '$RUN_NAME'. It keeps running on $NODE —" \
        "re-run the same target to reattach." >&2
    exit 130
}
trap on_interrupt INT

kill_stale_viewers
state="$(run_state)"
if [[ "$state" == running && "${K7_REMOTE_RESTART:-0}" == 1 ]]; then
    pid="$(node_sh "cat '$RUN_DIR/pid'")"
    echo "==> K7_REMOTE_RESTART=1: killing in-flight '$RUN_NAME' (process group $pid)"
    node_sh "kill -TERM -$pid 2>/dev/null; sleep 3; kill -KILL -$pid 2>/dev/null; true"
    # Its holder is waiting on a status file that will never arrive; without
    # this the restart would sit out the whole start grace.
    release_workspace_lock
    state=none
fi

if [[ "$state" == running ]]; then
    echo "==> '$RUN_NAME' is already running on $NODE (pid $(node_sh "cat '$RUN_DIR/pid'")) — reattaching," \
        "not restarting. Skipping rsync: its sources are what that run is building."
else
    start_run
fi

echo "==> Node log: $NODE:$RUN_DIR/log — local copy: ${LOCAL_LOG#"$REPO_ROOT"/}"
stream_run
