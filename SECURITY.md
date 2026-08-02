# Security policy

## Supported versions

Security fixes are applied to the latest public release and the default branch. Older releases may
not receive patches.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability
reporting flow:

https://github.com/ItsNishi/Nephron/security/advisories/new

Include the affected version or commit, the relevant input channel, reproduction steps, observed
and expected behavior, and the security impact. Minimize live secrets and personal data in the
report. A small synthetic proof of concept is preferred over a production payload or dataset dump.

Relevant reports include detector bypasses with practical impact, normalization inconsistencies,
configuration behavior that silently disables protection, sensitive-data disclosure, and package
or build-pipeline vulnerabilities.

Please allow time to validate and coordinate a fix before public disclosure.
