"use client";

import * as React from "react";

import type { Credential } from "@/lib/types";

import { fmtTime } from "./format";

export function CredsTab({ credentials, loading }: { credentials: Credential[]; loading: boolean }) {
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-2">
        <h2 className="text-sm font-medium">凭据台账</h2>
        <span className="text-muted-foreground text-xs">{credentials.length} 条（列表不含明文）</span>
      </div>
      <div className="overflow-x-auto rounded-md border">
        <table className="w-full text-left text-sm">
          <thead className="bg-muted/50 text-muted-foreground">
            <tr>
              <th className="px-3 py-2 font-medium">ID</th>
              <th className="px-3 py-2 font-medium">类型</th>
              <th className="px-3 py-2 font-medium">用户</th>
              <th className="px-3 py-2 font-medium">域</th>
              <th className="px-3 py-2 font-medium">脱敏</th>
              <th className="px-3 py-2 font-medium">来源</th>
              <th className="px-3 py-2 font-medium">任务</th>
              <th className="px-3 py-2 font-medium">登记时间</th>
            </tr>
          </thead>
          <tbody>
            {credentials.length === 0 ? (
              <tr>
                <td className="text-muted-foreground px-3 py-6 text-center" colSpan={8}>
                  {loading ? "加载中…" : "暂无凭据"}
                </td>
              </tr>
            ) : (
              credentials.map((c) => (
                <tr key={String(c.id)} className="border-t">
                  <td className="px-3 py-2 font-mono">{c.id}</td>
                  <td className="px-3 py-2">{c.cred_type}</td>
                  <td className="px-3 py-2">{c.username || "—"}</td>
                  <td className="px-3 py-2">{c.domain || "—"}</td>
                  <td className="px-3 py-2 font-mono text-xs">{c.secret_masked || "****"}</td>
                  <td className="max-w-xs truncate px-3 py-2" title={c.source}>
                    {c.source || "—"}
                  </td>
                  <td className="px-3 py-2">{c.task_id || "—"}</td>
                  <td className="px-3 py-2 whitespace-nowrap">{fmtTime(c.created_at)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
