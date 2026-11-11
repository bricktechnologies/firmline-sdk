# Security policy

## Reporting a vulnerability

Report a vulnerability in this SDK privately, through GitHub's private vulnerability reporting:
<https://github.com/bricktechnologies/firmline-sdk/security/advisories/new> (the «Report a
vulnerability» button in the Security tab). Do not open a public issue, pull request or discussion
for it.

Please include what you can of:

- the component (core library, Linux agent, container image, release workflow) and the version or
  commit;
- what an attacker can do and under which conditions (network position, access to the device, a
  relay of the site);
- the steps or a proof of concept to reproduce it.

The report reaches Brkt, the maintainer of the SDK and of the Firmline platform. A vulnerability of
the Firmline service itself can be reported the same way: say so in the report.

## What happens next

- Brkt confirms that the report was received and keeps you informed in the advisory.
- The fix is prepared privately; a new release of the SDK is published with it.
- The advisory is then published on GitHub, with a CVE identifier when one applies, and with credit
  to you unless you prefer otherwise.

Please keep the details private until the advisory is published.

## Supported versions

Fixes go into the latest release of the SDK. Until the first release is published, fixes go into
`main`. Devices should run the latest release.

Only the official sources listed in the [README](README.md#official-sources-and-support) are
covered: a modified copy of the SDK is the responsibility of whoever modifies it.
