# Ethical & Legal Boundaries

## Mandatory Rules

This project is strictly limited to **local demo applications and
authorized testing environments**.

- Do **not** scan, exploit, bypass, attack, or test real public
  applications, client infrastructure, production environments, or
  third-party systems without explicit written authorization from No
  Breach.
- Do **not** implement credential theft, phishing, malware, destructive
  exploitation, unauthorized scanning, or publish exploit material against
  real systems.
- All vulnerable code is written for local, educational, authorized use
  only, inside intentionally vulnerable demo applications built for this
  project.

## Technical Enforcement

- The DAST rule engine (Week 3) must validate every target against an
  allowlist (`localhost`, `127.0.0.1`, and the Docker Compose service
  network) before sending any request, and refuse to run against anything
  else. This is a hard requirement, not optional hardening.
- The SSRF demo feature (vulnerability #3) is the one place in this project
  where the *demo app itself* makes outbound requests based on user input.
  Its outbound target must also be constrained to the local Docker network
  in the vulnerable version, so the "vulnerability" is demonstrable without
  the demo app ever being able to reach the real internet.

## Why This Matters

The value of this platform is in the *rules and methodology* being
reusable and demonstrable — not in the vulnerable code being realistic
enough to run against anything real. Keeping demo apps clearly separate
from production-grade software, and clearly separate from the real
network, is what makes this safe to build, share, and use for training.
