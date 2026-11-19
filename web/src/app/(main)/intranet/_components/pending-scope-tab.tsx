"use client";

import * as React from "react";

import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { PendingScopeRow } from "@/lib/types";

import { fmtTime } from "./format";

export function PendingScopeTab({
  taskId,
}: {
  taskId?: string;
}) {
  const [items, setItems] = React.useState<PendingScopeRow[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [notice, setNotice] = React.useState<string | null>(null);

  const load = React.useCallback(() => {
    if (!taskId) {
      setItems([]);
      return;
    }
    setLoading(true);
    api
      .pendingScope(taskId, true)
      .then(setItems)
      .catch((err: unknown) => {
        setNotice(err instanceof Error ? err.message : String(err));
      })
      .finally(() => setLoading(false));
  }, [taskId]);

  React.useEffect(() => {
    load();
  }, [load]);

  const decide = (row: PendingScopeRow, action: "approve" | "dismiss") => {
    setNotice(null);
    api
      .decidePendingScope(row.id, action)
      .then(() => load())
      .catch((err: unknown) => {
        setNotice(err instanceof Error ? err.message : String(err));
      });
  };

  if (!taskId) {
    return <p className="text-muted-foreground text-sm">选择一个任务后可审批待授权网段。</p>;
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-2">
        <h2 className="text-sm font-medium">待授权网段</h2>
        <Button size="sm" variant="outline" className="ml-auto" onClick={load} disabled={loading}>
          刷新
        </Button>
      </div>
      {notice ? <p className="text-muted-foreground text-xs">{notice}</p> : null}
      <div className="overflow-x-auto rounded-md border">
        <table className="w-full text-left text-sm">
          <thead className="bg-muted/50 text-muted-foreground">
            <tr>
              <th className="px-3 py-2 font-medium">网段</th>
              <th className="px-3 py-2 font-medium">状态</th>
              <th className="px-3 py-2 font-medium">命中</th>
              <th className="px-3 py-2 font-medium">首次发现</th>
              <th className="px-3 py-2 font-medium">操作</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 ? (
              <tr>
                <td className="text-muted-foreground px-3 py-6 text-center" colSpan={5}>
                  {loading ? "加载中…" : "暂无待授权网段"}
                </td>
              </tr>
            ) : (
              items.map((row) => (
                <tr key={row.id} className="border-t">
                  <td className="px-3 py-2 font-mono">{row.value}</td>
                  <td className="px-3 py-2">{row.status}</td>
                  <td className="px-3 py-2">{row.hits}</td>
                  <td className="px-3 py-2 whitespace-nowrap">{fmtTime(row.first_seen)}</td>
                  <td className="px-3 py-2">
                    {row.status === "pending" ? (
                      <div className="flex gap-2">
                        <Button size="sm" onClick={() => decide(row, "approve")}>
                          批准
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => decide(row, "dismiss")}>
                          忽略
                        </Button>
                      </div>
                    ) : (
                      "—"
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
