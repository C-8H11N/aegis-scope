# Security policy

[English](SECURITY.md) | [简体中文](SECURITY.zh-CN.md)

## Supported versions

Only the latest release on the default branch receives security fixes during the alpha.

## Reporting a vulnerability

Do not open a public issue containing a vulnerability, secret, real target, or evidence.
Use GitHub private vulnerability reporting after the repository is published, or contact the
maintainer through a private channel documented in the eventual GitHub profile.

Include the affected version, minimal reproduction using synthetic data, expected behavior,
actual behavior, and suggested remediation. Do not test this project against systems you are
not explicitly authorized to assess.

## Trust boundaries

- Model output is untrusted.
- User-supplied scope and program text is untrusted until validated.
- Target responses and imported Burp data are untrusted.
- The Windows control plane owns authorization and long-term evidence.
- The Kali runner owns only bounded execution and temporary redacted output.
- SSH authenticates transport; the stage contract authorizes behavior.
