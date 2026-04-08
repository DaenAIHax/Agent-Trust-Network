# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Cullis, please report it responsibly.

**Do not open a public GitHub issue.**

### How to Report

**Email: [security@cullis.io](mailto:security@cullis.io)** — preferred channel.

This mailbox is monitored continuously by the maintainers. Please include
"SECURITY" or a CVE-style identifier in the subject line to make sure your
report is triaged quickly.

Alternative channel: [GitHub's private vulnerability reporting](https://github.com/cullis-security/cullis/security/advisories/new) if you cannot send email.

Both channels keep the report confidential until a fix is available. We do
**not** want public GitHub issues, X/Twitter posts, or blog posts about
vulnerabilities before a coordinated disclosure window has passed.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 7 days
- **Fix timeline:** Depends on severity, typically within 30 days
- **Public disclosure:** 90 days after report, or when fix is released (whichever comes first)

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest on `main` | Yes |
| Older commits | No |

## Security Design

Cullis is built with security as a core design principle:

- x509 PKI with 3-tier certificate chain
- DPoP token binding (RFC 9449) — no plain Bearer tokens
- E2E encryption (AES-256-GCM + RSA-OAEP) — broker never reads plaintext
- Default-deny session policy with federated PDP webhooks
- Append-only cryptographic audit log
- Certificate thumbprint pinning
- Rate limiting on all public endpoints

For a full security architecture overview, see the [README](README.md#security-architecture).
