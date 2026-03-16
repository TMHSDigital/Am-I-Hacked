# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.5.x   | Yes       |
| 0.4.x   | Yes       |
| 0.3.x   | No        |
| < 0.3   | No        |

## Scope

**Am I Hacked?** is a local, read-only security assessment tool. It does not expose network services, store data remotely, or run as a persistent agent. Vulnerabilities in scope include:

- False negatives that would cause a genuinely compromised system to report as clean (detection logic bugs)
- Code execution bugs — scenarios where running the tool on a compromised system could allow the attacker to escalate or persist via the tool itself
- Insecure handling of API keys or user-supplied config that leaks credentials
- Report injection — malicious finding data that executes code when the HTML report is opened

Out of scope:

- False positives (legitimate software flagged as suspicious) — open a [Detection Request](https://github.com/TMHSDigital/Am-I-Hacked/issues/new?template=detection_request.md) instead
- Issues requiring physical access to the machine being scanned
- Findings about the user's own environment surfaced by the tool (that's the point)

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Use GitHub's [private vulnerability reporting](https://github.com/TMHSDigital/Am-I-Hacked/security/advisories/new) to submit a report confidentially. Include:

1. A description of the vulnerability and its impact
2. Steps to reproduce or a proof-of-concept
3. The version of the tool affected
4. Any suggested fix if you have one

## Response Timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgement | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix or mitigation | Depends on severity — critical issues prioritized |
| Public disclosure | Coordinated with reporter after fix is released |

We follow responsible disclosure and will credit reporters in the release notes unless anonymity is requested.
