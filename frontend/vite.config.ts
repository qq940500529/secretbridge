// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import { readFileSync } from "node:fs";
const packageVersion = (
  JSON.parse(
    readFileSync(new URL("./package.json", import.meta.url), "utf8"),
  ) as { version: string }
).version;

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    {
      name: "secretbridge-build-metadata",
      generateBundle() {
        this.emitFile({
          type: "asset",
          fileName: "secretbridge-build.json",
          source: JSON.stringify({
            format_version: 1,
            version: packageVersion,
          }),
        });
      },
    },
  ],
  build: {
    target: "es2022",
    sourcemap: true,
  },
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8787",
        changeOrigin: false,
        ws: true,
      },
    },
  },
});
