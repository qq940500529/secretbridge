// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

export function loadPlaywright() {
  return require(process.env.PLAYWRIGHT_MODULE || "playwright");
}

export function selectedBrowser() {
  const name = process.env.SECRETBRIDGE_BROWSER || "chromium";
  if (!new Set(["chromium", "firefox", "webkit"]).has(name)) {
    throw new Error(`unsupported browser engine: ${name}`);
  }
  return name;
}

export async function launchBrowser() {
  const name = selectedBrowser();
  const playwright = loadPlaywright();
  const channel = name === "chromium" ? process.env.PLAYWRIGHT_CHANNEL : undefined;
  return {
    browser: await playwright[name].launch({ headless: true, channel }),
    name,
  };
}

export function assertNoSeriousAccessibilityViolations(results, assert) {
  const violations = results.violations.filter((item) =>
    ["serious", "critical"].includes(item.impact),
  );
  assert.deepEqual(
    violations.map((item) => ({
      id: item.id,
      impact: item.impact,
      targets: item.nodes.slice(0, 5).flatMap((node) => node.target),
    })),
    [],
    "No serious or critical WCAG A/AA violations",
  );
}
