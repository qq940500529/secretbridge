# Security policy

## Supported versions

There are no supported application releases yet. This repository is a design-stage project and must not be used with real credentials. No independent security audit has been completed.

## Private reporting

Use GitHub's **Report a vulnerability** feature at:

https://github.com/qq940500529/secretbridge/security/advisories/new

Include a synthetic reproduction, affected commit, expected/actual behavior and impact. Do not include live passwords, personal records or production exports. If private reporting is unavailable, open a public issue requesting a private channel **without vulnerability details**; wait for a private channel before sharing sensitive information.

The maintainer will assess reports as capacity permits; no response-time SLA is promised. Coordinate disclosure after assessment and a remediation plan rather than posting exploit details with live targets.

## Boundaries

Output masking is not a sandbox. An AI with unrestricted access to the credential owner's account can bypass application-level controls. The planned secure mode requires a tested OS/process/identity boundary and narrow operation adapters. See [the threat model](docs/安全模型与验收.md).

If a live credential is exposed, revoke or rotate it at its source first. Removing a commit, closing an issue or deleting a file does not guarantee recovery of a published secret.
