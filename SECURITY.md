# Security policy

## Reporting a vulnerability

Please report a suspected vulnerability **privately** through GitHub's private vulnerability
reporting: <https://github.com/hupe1980/rawether/security/advisories/new>.

Do not open a public issue, pull request or discussion for it. Include the OS and version
(Linux kernel release or macOS build), the rawether version, the configuration, and the smallest
program and frames that show the problem.

## Scope

What rawether defends against, and what it does not, is described in the
[threat model](THREAT_MODEL.md), with the test that guards each class. Reports about
out-of-scope classes (kernel or driver bugs, frame authenticity) are still welcome, but may be
answered with a pointer upstream.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| Earlier | No |

Before 1.0 only the latest minor version gets fixes; there are no backports.

## What to expect

You can expect an acknowledgement within a week. A confirmed vulnerability gets a fix, an entry
in the threat model, and a test that guards it.
