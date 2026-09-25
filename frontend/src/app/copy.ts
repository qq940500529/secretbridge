// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { Language } from "./preferences";

export interface Copy {
  credentials: string;
  targets: string;
  operations: string;
  taskTemplates: string;
  taskApprovals: string;
  taskRuns: string;
  terminal: string;
  audit: string;
  settings: string;
  overview: string;
  subtitle: string;
  service: string;
  online: string;
  offline: string;
  checking: string;
  paired: string;
  unpaired: string;
  pairing: string;
  authError: string;
  localOnly: string;
  statusTitle: string;
  apiVersion: string;
  runtimeMode: string;
  syntheticOnly: string;
  credentialConfiguration: string;
  controlledOperations: string;
  configurationStorage: string;
  memoryOnly: string;
  localDatabase: string;
  realCredentials: string;
  disabled: string;
  enabled: string;
  futureModule: string;
  futureBody: string;
  collapse: string;
  expand: string;
  skipContent: string;
  primaryNavigation: string;
  switchLanguage: string;
  connectionStatus: string;
  feedback: string;
}

export const copy: Record<Language, Copy> = {
  "zh-CN": {
    credentials: "凭据",
    targets: "连接",
    operations: "任务",
    taskTemplates: "任务模板",
    taskApprovals: "授权与确认",
    taskRuns: "执行与结果",
    terminal: "终端",
    audit: "历史",
    settings: "设置",
    overview: "服务与页面设置",
    subtitle: "检查本机服务、存储方式和当前页面的配对状态。",
    service: "本地服务",
    online: "在线",
    offline: "未连接",
    checking: "检查中",
    paired: "已配对",
    unpaired: "等待启动配对",
    pairing: "正在配对",
    authError: "配对失败",
    localOnly: "仅限本机",
    statusTitle: "运行状态",
    apiVersion: "接口版本",
    runtimeMode: "运行模式",
    syntheticOnly: "仅合成运行",
    credentialConfiguration: "凭据配置",
    controlledOperations: "受控操作",
    configurationStorage: "配置存储",
    memoryOnly: "仅内存（重启清空）",
    localDatabase: "本机 SQLite 数据库",
    realCredentials: "凭据代用",
    disabled: "未启用",
    enabled: "已启用",
    futureModule: "请先配对本机服务",
    futureBody:
      "请在这台电脑上运行已安装程序的 open 命令，程序会打开一次性配对页面，无需复制或手动输入配对码。若配对失败，请重新运行 open；刷新旧页面不能恢复已使用的链接。",
    collapse: "收起导航",
    expand: "展开导航",
    skipContent: "跳到主要内容",
    primaryNavigation: "主导航",
    switchLanguage: "切换到英文",
    connectionStatus: "连接状态",
    feedback: "反馈问题",
  },
  en: {
    credentials: "Credentials",
    targets: "Connections",
    operations: "Tasks",
    taskTemplates: "Templates",
    taskApprovals: "Authorization",
    taskRuns: "Execution & results",
    terminal: "Terminal",
    audit: "History",
    settings: "Settings",
    overview: "Service and page settings",
    subtitle:
      "Inspect the local service, configuration storage and this page's pairing status.",
    service: "Local service",
    online: "Online",
    offline: "Disconnected",
    checking: "Checking",
    paired: "Paired",
    unpaired: "Awaiting startup pairing",
    pairing: "Pairing",
    authError: "Pairing failed",
    localOnly: "Loopback only",
    statusTitle: "Runtime status",
    apiVersion: "API version",
    runtimeMode: "Runtime mode",
    syntheticOnly: "Synthetic only",
    credentialConfiguration: "Credential configuration",
    controlledOperations: "Controlled operations",
    configurationStorage: "Configuration storage",
    memoryOnly: "Memory-only (cleared on restart)",
    localDatabase: "Local SQLite database",
    realCredentials: "Credential use",
    disabled: "Disabled",
    enabled: "Enabled",
    futureModule: "Pair with the local service",
    futureBody:
      "Run the installed program's open command on this computer. It opens the one-time pairing page; no code needs to be copied or entered. If pairing fails, run open again. Reloading an old page cannot restore a used link.",
    collapse: "Collapse navigation",
    expand: "Expand navigation",
    skipContent: "Skip to main content",
    primaryNavigation: "Primary navigation",
    switchLanguage: "Switch to Chinese",
    connectionStatus: "Connection status",
    feedback: "Feedback",
  },
};
