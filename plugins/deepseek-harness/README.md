# SecretBridge for DeepSeek Harness

An installable native Harness bundle: the official MCP client owns protocol transport, reconnects and tool registration; a small Cordis plugin supplies SecretBridge-specific operating guidance. No build or lifecycle scripts run when installing this package. SecretBridge credentials stay in the local broker.

## Install

Install and initialize SecretBridge first. Export this bundle to a new absolute destination:

```text
secretbridge client-plugin deepseek-harness <absolute-new-directory>
dsh plugin --profile <profile> add <absolute-new-directory>
dsh --profile <profile> --dump-config
```

The exporter personalizes the prebuilt bundle with the stable installed MCP launcher. Upgrade or rollback of SecretBridge does not require rebuilding this plugin. The destination must not exist. Do not register a second SecretBridge MCP client in the same profile.

Use Harness 0.2.0-rc.1 or a compatible 0.2.x runtime satisfying the declared `@deepseek-ai/dsh` peer range. Harness checks this requirement against its running app-boot version, not the individual service package versions. The upper bound also excludes future 0.3 prereleases. This optional peer is a host compatibility declaration, not a request to download another Harness runtime. Older npm packages are not equivalent to the current plugin API; do not bypass compatibility checks. The host provides the MCP client and system-prompt services. The bundle does not vendor, patch or rebuild them.

## Verify and remove

Check for `mcp__secretbridge__secretbridge_terminal_capabilities` and call it without parameters. Then call `mcp__secretbridge__secretbridge_list_catalog` to inspect metadata and language. This establishes connectivity, not permission to run a business operation. The person must still approve pending operations in SecretBridge.

```text
dsh plugin --profile <profile> remove dsh-secretbridge
```

Removing the bundle unloads its MCP client and guidance. It does not stop the local broker or remove credentials. SecretBridge uninstall makes the stable launcher unavailable, so reinstall the broker before reconnecting.

## Upstream contracts

- [Bundle publication and installation](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/user/develop/basic/publish.md)
- [Official MCP client](https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/mcp/mcp-client/README.md)
- [System-prompt registration](https://deepseek-harness.github.io/deepseek-harness/en/reference/subsystems/system-prompt)

Guidance is not an enforcement boundary. SecretBridge enforces approvals, credential access and filtering; Harness's other tools remain governed by Harness permissions.
