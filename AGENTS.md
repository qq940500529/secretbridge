# Repository instructions for automation agents

SecretBridge is a local credential-use broker. Preserve its trust boundary while editing, testing or deploying it.

## Before work

- Read `README.md`, `SECURITY.md`, `CONTRIBUTING.md` and the task-relevant document under `docs/`.
- For deployment, follow `docs/getting-started/自动化部署运行手册.md` and `docs/getting-started/安装与服务管理.md`.
- Inspect the current branch, commit and working tree. Preserve unrelated user changes.

## Security

- Use only synthetic credentials. Never read existing credential-store entries or place secrets in commands, environment variables, source, logs, screenshots, reports, issues or pull requests.
- Keep the broker loopback-only. Do not weaken OS security, permissions, TLS, host-key verification, approval checks or output filtering to make a test pass.
- Do not add a secret read/export API. Web approval decisions remain unavailable to MCP.
- Redact usernames, hostnames, personal paths, private addresses and credential values from public evidence.

## Changes and verification

- Use the pinned tool versions and lock files. Do not skip failing assertions.
- Update tests and reader-facing documentation with behavior changes.
- Run the repository, Python, Web and Rust gates listed in `docs/development/开发者入门.md`; run package/database/browser/platform acceptance when the change touches those areas.
- Report unexecuted platform checks as limited. Do not present fixtures, headless browsers or process restarts as real desktop, native credential-store or full reboot evidence.
