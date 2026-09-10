// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createRoot } from "react-dom/client";

import { App } from "./App";
import "./styles.css";

const root = document.getElementById("root");
if (!root) {
  throw new Error("Missing application root");
}

// Pairing consumes a one-time capability. Avoid development-only StrictMode
// effect replay, which would submit that capability twice.
createRoot(root).render(<App />);
