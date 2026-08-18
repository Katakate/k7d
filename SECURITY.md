# Security Policy

## Supported versions

k7d is pre-1.0. Security fixes land on the latest release only until 1.0.0.

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |
| < 0.1   | ❌        |

## Reporting a vulnerability

Email **security@katakate.org** (preferred), or open a private GitHub
Security Advisory on [Katakate/k7d](https://github.com/Katakate/k7d).

Include impact, reproduction steps or a PoC, and affected version / commit.
We aim to acknowledge within 72 hours.

Please do not open a public issue for security-sensitive reports.

## Threat model (honest summary)

k7d is built for fleets of **your own** environments (RL rollouts, agent
evals, sandboxes you control) — not for hostile multi-tenant isolation
between sibling forks of the same tenant.

| Boundary | Strength |
|----------|----------|
| Guest → host | KVM hardware isolation |
| Between unrelated VMs / trees | Separate bridges, separate guest memory files |
| Between sibling CoW forks of one tree | **Weaker** — parent and child share one daemon address space by design (live CoW requires it) |

Additional limits:

- Single host, Linux x86_64 + KVM only; no cross-node fork yet
- Young codebase (≤30k LOC VMM + shim); no third-party security audit yet
- Control socket `/run/k7d/k7d.sock` is local Unix — protect host access

For product-facing detail see the docs site security page and the README
"Security model & limitations" section.

## Responsible disclosure

Coordinate disclosure; we will credit reporters unless anonymity is requested.
