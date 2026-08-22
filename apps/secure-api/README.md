# secure-api

The Week 6 secure counterpart to `apps/vulnerable-api/`. Same routes,
same seed data, same test accounts — every fix here is designed to be
verifiable by re-running the exact same DAST rules and SAST rules from
Weeks 3-5 against this app instead, and confirming they no longer fire.

See [`../../docs/secure-fixes.md`](../../docs/secure-fixes.md) for what
changed and why, per vulnerability.
