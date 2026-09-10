# Contributing

SecretBridge is in the design stage. Start with a focused issue or design proposal; do not submit a large implementation that silently changes the trust model.

## Before submitting

1. Read the README, threat model and platform specification.
2. Use only synthetic data. Never include credentials, private endpoints, personal directories, business exports or customer screenshots.
3. State the source and license of imported code/assets. Do not copy repositories with no license.
4. Disclose AI-assisted portions and explain your review and tests. AI generation is not a provenance or correctness guarantee.
5. Keep changes focused and update relevant documentation and tests.
6. Run `python tools/check_repository.py` and `python -m unittest discover -s tests -v` with Python 3.11+.

Application build commands will be documented when code exists; the checks above do not build a desktop app.

## Licensing and sign-off

Contribute only material you have the right to license under AGPL-3.0-only (or explicitly documented compatible third-party terms). Sign off commits with `git commit -s` after reading the [Developer Certificate of Origin 1.1](https://developercertificate.org/). Sign-off is a contributor assertion, not a copyright transfer. Configure an appropriate public/noreply email before committing. Do not falsely sign for another person.

The maintainer reviews safety scope, provenance, behavior, tests and docs; self-reported test success is not sufficient. Security-sensitive code should receive independent review before stable release. This is a requirement to establish, not a claim that multiple maintainers currently exist.

## Reports

Use public issues for non-sensitive bugs and proposals. Use [SECURITY.md](SECURITY.md) for vulnerabilities. Never post a real secret to demonstrate a bug.
