# Security Policy — VERA Protocol

## Supported Versions

| Version | Supported |
| --- | --- |
| v2.7.1 | ✅ |
| < v2.7.0 | ❌ Deprecated — upgrade immediately |

Only the latest tagged release of vera_core_v271_verified.py is supported.
Older versions have known structural bugs BUG-1 to BUG-9 and must not be used in production.

## Reporting a Vulnerability

Do NOT open a public GitHub issue for security problems.

Contact: tahahouari@hotmail.fr

Include in your report:
1. VERA version + git SHA
2. Branch: radio | edge | artist
3. Proof-of-concept or steps to reproduce
4. Impact: data leakage, bypass INV-2, epsilon exhaustion, etc.

SLA: We acknowledge within 72h. We aim to patch critical issues in 7 days.
Critical = breaks INV-1, INV-2, INV-4, or allows raw data extraction.

## Scope

In-scope:
- vera_core_v271_verified.py — all INV-1 to INV-8 violations
- Bypass of N_max=5, epsilon_output, or TTL=7d
- Reconstruction error < 1% p10 on N=5
- Side-channel via audit_state() or audit_token()

Out-of-scope:
- vera_nav_final.py — report privately via email.
- Rate-limit bypass — this is INFRA, not core.
- Social engineering, physical access, compromised VERA_SERVER_KEY
- Denial of service via CPU exhaustion

## Disclosure Policy

1. You report privately to us.
2. We confirm + fix + release patch.
3. We credit you in CHANGELOG.md unless you request anonymity.
4. Public disclosure 90 days after our fix, or earlier if mutually agreed.

No bug bounty program yet. Good-faith researchers get attribution + thanks.

## Hardening Assumptions

VERA Core is FINAL LOCK v2.5. It assumes:
1. secrets module is CSPRNG — not random
2. Host OS provides monotonic time.time()
3. NAV layer enforces rate-limiting. Core alone does NOT prevent cross-session averaging.

Deploying Core without NAV violates the threat model. See VERA_INFRA_Spec_v11.pdf.

## Contact

Taha Houari — VERA Protocol
tahahouari@hotmail.fr
github.com/taha-vera/Vera-protocole-
