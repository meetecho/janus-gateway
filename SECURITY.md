# Janus WebRTC Server -- Security & Vulnerability Handling Policy

*Maintained by Meetecho as open-source software steward under Article 24 of the EU Cyber Resilience Act (Regulation (EU) 2024/2847)*

**Last updated:** 10th of September, 2026· **Version:** 1.0

---

## 1. Why this document exists

This policy fulfils Meetecho's obligations as an open-source software steward of Janus under Article 24 of the EU Cyber Resilience Act. It exists to:

- explain how vulnerabilities in Janus get reported, triaged, and fixed;
- encourage the community to report issues responsibly; and
- give EU market surveillance authorities a single, verifiable reference document if they ever ask for one (Art. 24(2)).

This is *not* a certification, warranty, or conformity claim. Janus is free and open-source software distributed under the GPLv3, without any guarantee of fitness for a particular purpose.

## 2. Scope

This policy covers the Janus WebRTC Server core project as published at https://github.com/meetecho/janus-gateway, and its officially maintained plugins/transports in that repository. It does not cover third-party forks, unofficial plugins, or downstream commercial products built on top of Janus by other companies (those parties have their own CRA obligations as manufacturers, if applicable to them).

## 3. How to report a vulnerability

- **Contact:** `security@meetecho.com`
- **What to include:** affected version/commit, reproduction steps or PoC, potential impact, whether it's already public or being exploited.
- **Response time:** we aim to acknowledge reports within 2-3 business days.

We ask reporters to give us a reasonable window to investigate and patch before any public disclosure ("coordinated disclosure"). We do not take legal action against good-faith security researchers who follow this process. We don't run a paid bug-bounty program, so we don't offer monetary compensation for security reports.

## 4. How we handle a reported vulnerability

1. **Triage** -- confirm the issue, assess severity and affected versions.
2. **Fix** -- develop and test a patch on a private branch where premature disclosure would put users at risk; otherwise fix in the open as normal.
3. **Release** -- publish a patched release together with a security advisory (GitHub Security Advisories / CHANGELOG entry) describing the issue, affected versions, and mitigation.
4. **Credit** -- the reporter is credited (unless they ask to stay anonymous).

Target timelines:

| Severity | Target time to patch/mitigation |
|---|---|
| Critical (remote code execution, auth bypass) | 7 days |
| High | 14 days |
| Medium/Low | Next regular release |

These are targets, not contractual SLAs. Janus is maintained by a small team, and timelines can shift for genuinely complex issues.

## 5. Actively exploited vulnerabilities and severe incidents

If Meetecho becomes aware that a vulnerability in Janus is being actively exploited in the wild, or of a severe incident affecting the infrastructure we use to develop Janus (e.g. our build/CI systems, source repositories), we will, to the extent required by Article 14 of the CRA:

- notify ENISA via the CRA Single Reporting Platform within 24 hours of awareness (early warning);
- submit a full notification within 72 hours;
- submit a final report within 14 days (exploited vulnerability) or one month (severe incident) of a fix or resolution being available.

This obligation is limited to Meetecho's own development infrastructure for Janus. We are not responsible for reporting on how third parties deploy or operate Janus in their own products.

## 6. Cooperation with market surveillance authorities

Upon a reasoned request from an EU market surveillance authority, Meetecho will provide this policy and related documentation, in a language the authority can understand, in electronic or paper form, as required by Article 24(2).

Point of contact for such requests: `security@meetecho.com`.

## 7. Encouraging community vulnerability reporting

Contributors and downstream users are encouraged to:

- report suspected vulnerabilities privately using the channel in Section 3, rather than as public GitHub issues;
- share security-relevant findings (including "near misses", situations where an issue was possible but wasn't exploited) so the wider community can learn from them;
- follow secure coding practices described in the documentation.

## 8. Supported versions

Notice that, while there are multiple versions of Janus, they're simply tagged versions of the `master` and `0.x` Janus branches. As such, once they're tagged as versions, they won't receive security updates. The only way to get security updates that are published after a specific version is to either use a more recent tagged version (if it includes the security fix) or refer to the `master` branch instead, which is where active development focuses on (or, for legacy deployments, the `0.x` branch).

Refer to the [CHANGELOG.md](CHANGELOG.md) file for information of what each version adds, including security related fixes.

## 9. Review

This policy is reviewed at least once a year, or after any significant security incident, by the Meetecho team.
