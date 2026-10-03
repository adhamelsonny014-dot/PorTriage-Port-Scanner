# Security Policy

## Supported versions

Only the latest release of PorTriage receives security fixes.

| Version | Supported |
|---|---|
| 2.x | ✅ |
| < 2.0 | ❌ |

## Reporting a vulnerability

If you find a security problem **in PorTriage itself** — for example, a crafted nmap or API response that leads to code execution, a path traversal in report output, or unsafe handling of API keys — please **do not open a public issue**.

Instead, report it privately through GitHub: open the repository's **Security** tab and click **Report a vulnerability**.

Please include:
- the PorTriage version (`python portriage.py --help` shows it in the banner),
- steps to reproduce, and
- the impact you expect.

You can expect an acknowledgement within a few days. Once a fix is released, you'll be credited in the release notes unless you'd rather stay anonymous.

## Out of scope

- Vulnerabilities in the services that PorTriage *finds* on scanned hosts — report those to the affected vendor.
- Inaccurate or missing CVE data from NVD, OSV, Vulners, CISA KEV or FIRST EPSS — report those to the data provider.
- False positives caused by version-based matching (a known limitation, see the README).
