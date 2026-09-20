// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { Activity } from "lucide-react";

import type { ServiceStatus } from "./api";
import { ISSUE_URL, SECURITY_URL } from "./LegalConsent";
import type { Language } from "./preferences";

interface StatusCopy {
  overview: string;
  subtitle: string;
  localOnly: string;
  statusTitle: string;
  apiVersion: string;
  runtimeMode: string;
  controlledOperations: string;
  credentialConfiguration: string;
  syntheticOnly: string;
  configurationStorage: string;
  localDatabase: string;
  memoryOnly: string;
  realCredentials: string;
  enabled: string;
  disabled: string;
}

interface SettingsViewProps {
  text: StatusCopy;
  status: ServiceStatus | null;
  language: Language;
  onLanguageChange: (language: Language) => void;
  onReviewLegal: () => void;
}

export function SettingsView({
  text,
  status,
  language,
  onLanguageChange,
  onReviewLegal,
}: SettingsViewProps) {
  const settingsCopy =
    language === "zh-CN"
      ? {
          preferences: "语言、许可与反馈",
          language: "界面默认语言",
          languageHelp: "选择会保存在当前浏览器中，并在下次打开时继续使用。",
          legal: "许可协议与免责协议",
          legalHelp: "重新查看首次运行时同意的完整双语条款。",
          review: "查看协议",
          report: "提交普通问题",
          reportHelp:
            "使用合成数据复现并清理日志；不要公开真实凭据或私人地址。",
          security: "私密报告安全问题",
        }
      : {
          preferences: "Language, legal and feedback",
          language: "Default interface language",
          languageHelp:
            "The choice is saved in this browser and used the next time you open the app.",
          legal: "License Agreement and Disclaimer",
          legalHelp:
            "Review the complete bilingual terms accepted at first run.",
          review: "Review agreement",
          report: "Report a regular issue",
          reportHelp:
            "Reproduce with synthetic data and sanitize logs. Never publish real credentials or private addresses.",
          security: "Report a security issue privately",
        };
  return (
    <>
      <div className="mb-7 flex flex-wrap items-end justify-between gap-5">
        <div>
          <h1 className="m-0 text-3xl font-bold tracking-tight text-slate-950">
            {text.overview}
          </h1>
          <p className="mt-3 max-w-2xl text-base leading-7 text-slate-600">
            {text.subtitle}
          </p>
        </div>
        <span className="inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-600">
          <span className="size-2 rounded-full bg-emerald-500 shadow-[0_0_0_4px_rgba(16,185,129,0.12)]" />
          {text.localOnly}
        </span>
      </div>

      <section className="enterprise-surface">
        <div className="flex items-center justify-between border-b border-slate-200 px-5 py-4">
          <h2 className="m-0 text-base font-semibold text-slate-900">
            {text.statusTitle}
          </h2>
          <Activity className="size-5 text-cyan-600" aria-hidden="true" />
        </div>
        <dl className="divide-y divide-slate-200">
          <StatusDatum
            label={text.apiVersion}
            value={status?.api_version ?? "—"}
          />
          <StatusDatum
            label={text.runtimeMode}
            value={
              status?.mode === "controlled_operations"
                ? text.controlledOperations
                : status?.mode === "credential_configuration"
                  ? text.credentialConfiguration
                  : status?.mode === "synthetic_only"
                    ? text.syntheticOnly
                    : "—"
            }
          />
          <StatusDatum
            label={text.configurationStorage}
            value={
              status?.configuration_storage === "sqlite"
                ? text.localDatabase
                : status?.configuration_storage === "memory_only"
                  ? text.memoryOnly
                  : "—"
            }
          />
          <StatusDatum
            label={text.realCredentials}
            value={
              status?.real_credentials_enabled ? text.enabled : text.disabled
            }
          />
        </dl>
      </section>

      <section className="enterprise-surface mt-6">
        <div className="border-b border-slate-200 px-5 py-4">
          <h2 className="m-0 text-base font-semibold text-slate-900">
            {settingsCopy.preferences}
          </h2>
        </div>
        <div className="divide-y divide-slate-200">
          <div className="grid gap-4 px-5 py-5 md:grid-cols-[1fr_auto] md:items-center">
            <div>
              <h3 className="m-0 text-sm font-semibold text-slate-900">
                {settingsCopy.language}
              </h3>
              <p className="mb-0 mt-1 text-sm leading-6 text-slate-500">
                {settingsCopy.languageHelp}
              </p>
            </div>
            <div className="inline-flex w-fit rounded-lg border border-slate-300 bg-slate-50 p-1">
              {(["zh-CN", "en"] as const).map((option) => (
                <button
                  key={option}
                  type="button"
                  onClick={() => onLanguageChange(option)}
                  className={`rounded-md px-3 py-1.5 text-sm font-semibold ${
                    language === option
                      ? "bg-white text-cyan-800 shadow-sm"
                      : "text-slate-500 hover:text-slate-900"
                  }`}
                  aria-pressed={language === option}
                >
                  {option === "zh-CN" ? "简体中文" : "English"}
                </button>
              ))}
            </div>
          </div>
          <div className="grid gap-4 px-5 py-5 md:grid-cols-[1fr_auto] md:items-center">
            <div>
              <h3 className="m-0 text-sm font-semibold text-slate-900">
                {settingsCopy.legal}
              </h3>
              <p className="mb-0 mt-1 text-sm leading-6 text-slate-500">
                {settingsCopy.legalHelp}
              </p>
            </div>
            <button
              type="button"
              className="workbench-button"
              onClick={onReviewLegal}
            >
              {settingsCopy.review}
            </button>
          </div>
          <div className="grid gap-4 px-5 py-5 md:grid-cols-[1fr_auto] md:items-center">
            <div>
              <h3 className="m-0 text-sm font-semibold text-slate-900">
                {settingsCopy.report}
              </h3>
              <p className="mb-0 mt-1 text-sm leading-6 text-slate-500">
                {settingsCopy.reportHelp}
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <a
                href={ISSUE_URL}
                target="_blank"
                rel="noreferrer"
                className="workbench-button no-underline"
              >
                {settingsCopy.report}
              </a>
              <a
                href={SECURITY_URL}
                target="_blank"
                rel="noreferrer"
                className="workbench-button no-underline"
              >
                {settingsCopy.security}
              </a>
            </div>
          </div>
        </div>
      </section>
    </>
  );
}

function StatusDatum({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-1 px-5 py-3 sm:grid-cols-[14rem_1fr] sm:items-center">
      <dt className="text-sm font-medium text-slate-500">{label}</dt>
      <dd className="m-0 text-sm font-semibold text-slate-900">{value}</dd>
    </div>
  );
}
