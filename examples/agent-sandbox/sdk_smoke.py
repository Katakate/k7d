"""Upstream Python SDK, Tunnel mode (kubectl port-forward to sandbox-router,
router -> sandbox pod IP), against a k7d-backed warm pool.

usage: python sdk_smoke.py <namespace> <warmpool>
"""

import sys
import time

from k8s_agent_sandbox import SandboxClient
from k8s_agent_sandbox.models import SandboxLocalTunnelConnectionConfig

ns, pool = sys.argv[1:3]
client = SandboxClient(connection_config=SandboxLocalTunnelConnectionConfig())
t0 = time.monotonic()
sbx = client.create_sandbox(warmpool=pool, namespace=ns)
try:
    print(f"claim ready in {time.monotonic() - t0:.2f}s")
    r = sbx.commands.run("echo ok")
    assert r.exit_code == 0 and r.stdout.strip() == "ok", r
    r = sbx.commands.run("sh -c 'uname -r; grep -c hypervisor /proc/cpuinfo; nproc'")
    assert r.exit_code == 0, r
    print("guest kernel / hypervisor vCPUs / nproc:", r.stdout.split())
    sbx.files.write("k7d.txt", "hello from a k7d microVM")
    assert sbx.files.read("k7d.txt") == b"hello from a k7d microVM"
    print("SDK_OK")
finally:
    sbx.terminate()
