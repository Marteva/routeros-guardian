# Security policy

## Supported versions

Guardian for RouterOS is a small hobby project. Security fixes are made for
the **latest release** only; please update before reporting.

## Reporting a vulnerability

**Please do not report security vulnerabilities in public issues,
discussions or pull requests.**

Report them privately through GitHub's security advisories:
**[Report a vulnerability](https://github.com/Marteva/routeros-guardian/security/advisories/new)**
(repository → *Security* → *Report a vulnerability*).

Please include:

- the affected version (release, image tag or commit),
- RouterOS version and router model, if relevant,
- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- any suggested fix.

What to expect: an acknowledgement within about a week, an assessment and,
for confirmed issues, a fix and a published advisory. Response times are best
effort. You will be credited in the advisory unless you prefer otherwise.

## Scope

In scope: the Guardian code in this repository, the published container
images and release tarballs, the build scripts and the RouterOS setup
documentation (for example a setup step that weakens the router's security).

Out of scope: vulnerabilities in RouterOS itself (report them to MikroTik),
in third-party dependencies (report upstream; we will update), and issues
that require an attacker who already has administrative access to the
router.

## Hardening recommendations

See the [Security section of the README](README.md#security): least-privilege
API user restricted to the container IP, UI login enabled, UI and REST API
reachable from the LAN only, notification tokens entered in the UI rather
than in `/container envs`.
