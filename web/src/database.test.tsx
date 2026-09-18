// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { CommandEditor, emptyCommand } from "./CommandEditor";
import { emptyDatabase } from "./DatabaseEditor";
import { CommandReview } from "./CommandReview";
import { parseDatabaseResult, DatabaseResultView } from "./DatabaseResultView";
import type { ActionTemplate } from "./api";

describe("database query workflow", () => {
  const config = {
    ...emptyCommand,
    database: {
      ...emptyDatabase,
      operation: "query" as const,
      host: "db.example.com",
      query: "SELECT {{param:company}} AS company",
      columns: ["company"],
    },
  };
  it("has dedicated connection and SQL configuration in both languages", () => {
    for (const language of ["zh-CN", "en"] as const) {
      const html = renderToStaticMarkup(
        <CommandEditor
          value={config}
          onChange={() => {}}
          credentials={[]}
          language={language}
        />,
      );
      expect(html).toContain("MySQL");
      expect(html).toContain("PostgreSQL");
      expect(html).toContain("{{param:company}}");
      expect(html).not.toContain("Git 程序绝对路径");
      expect(html).not.toContain("Environment variable");
    }
  });
  it("does not show SQL or parameters for fixed connection checks", () => {
    const html = renderToStaticMarkup(
      <CommandEditor
        value={{ ...emptyCommand, database: emptyDatabase }}
        onChange={() => {}}
        credentials={[]}
        language="zh-CN"
      />,
    );
    expect(html).not.toContain("只读 SQL");
    expect(html).not.toContain("普通参数定义");
    expect(html).toContain("数据库密码引用");
  });
  it("reviews frozen connection, query, selected columns and bound input without secret IDs", () => {
    const html = renderToStaticMarkup(
      <CommandReview
        template={
          {
            command: {
              ...config,
              slots: [
                {
                  name: "database_password",
                  credential_id: "private-id",
                  injection: "protocol",
                  environment_variable: null,
                },
              ],
            },
            version: 1,
          } as ActionTemplate
        }
        expectedVersion={1}
        language="zh-CN"
        parameters={{ company: "100" }}
      />,
    );
    expect(html).toContain("db.example.com");
    expect(html).toContain("company");
    expect(html).toContain("100");
    expect(html).not.toContain("private-id");
  });
  it("parses only complete shaped database results and preserves numeric strings", () => {
    const text = JSON.stringify({
      kind: "database",
      columns: ["金额", "备注"],
      rows: [["12345678901234567890.123456", null]],
      truncated: true,
      cleanup_ok: true,
    });
    const parsed = parseDatabaseResult(text)!;
    expect(parsed.rows[0][0]).toBe("12345678901234567890.123456");
    expect(parseDatabaseResult(text.slice(0, -1))).toBeNull();
    expect(
      parseDatabaseResult('{"kind":"http","columns":[],"rows":[]}'),
    ).toBeNull();
    expect(
      parseDatabaseResult('{"kind":"database","columns":["x"],"rows":[[1]]}'),
    ).toBeNull();
    const html = renderToStaticMarkup(
      <DatabaseResultView result={parsed} zh={true} />,
    );
    expect(html).toContain("<table");
    expect(html).toContain("NULL");
    expect(html).toContain("未返回全部数据");
  });
  it("escapes cell markup and explains empty results", () => {
    const result = {
      columns: ["x"],
      rows: [["<script>bad</script>"]],
      truncated: false,
      cleanup_ok: true,
    };
    expect(
      renderToStaticMarkup(<DatabaseResultView result={result} zh={false} />),
    ).not.toContain("<script>");
    expect(
      renderToStaticMarkup(
        <DatabaseResultView result={{ ...result, rows: [] }} zh={true} />,
      ),
    ).toContain("没有匹配的数据");
  });
});
