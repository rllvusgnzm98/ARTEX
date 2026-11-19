"use client";

import * as React from "react";

import { Loader2Icon, RefreshCwIcon } from "lucide-react";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { ShellSession } from "@/lib/types";
import { cn } from "@/lib/utils";

import { fmtTime } from "./format";

export interface HostFilter {
  ip?: string;
  id?: string;
}

export function SessionsTab({
  sessions,
  loading,
  onReload,
  hostFilter,
  onClearFilter,
}: {
  sessions: ShellSession[];
  loading: boolean;
  onReload: () => void;
  hostFilter: HostFilter | null;
  onClearFilter: () => void;
}) {
  const [probing, setProbing] = React.useState<string | null>(null);
  const [notice, setNotice] = React.useState<string | null>(null);
  const [handoffTarget, setHandoffTarget] = React.useState<ShellSession | null>(null);
  const [handingOff, setHandingOff] = React.useState(false);

  const visible = React.useMemo(() => {
    if (!hostFilter) return sessions;
    return sessions.filter((s) => {
      if (hostFilter.ip && (s.url || "").includes(hostFilter.ip)) return true;
      if (hostFilter.id && String(s.host_asset_id) === String(hostFilter.id).replace(/^asset-/, "")) return true;
      return false;
    });
  }, [sessions, hostFilter]);

  const probe = (target: ShellSession) => {
    const key = String(target.id);
    setProbing(key);
    setNotice(null);
    api
      .probeSession(target.id)
      .then((r) => {
        setNotice(r.alive ? `会话 #${key} 探活成功` : `会话 #${key} 探活失败：${r.error || "已标 dead"}`);
        onReload();
      })
      .catch((err: unknown) => {
        setNotice(`探活请求失败：${err instanceof Error ? err.message : String(err)}`);
      })
      .finally(() => setProbing(null));
  };

  const confirmHandoff = () => {
    const target = handoffTarget;
    if (!target) return;
    setHandingOff(true);
    setNotice(null);
    api
      .handoffSession(target.id)
      .then((r) => {
        setNotice(`已创建内网子任务 #${r.task_id}（初始官方范围仅立足点 /32）`);
        setHandoffTarget(null);
        onReload();
      })
      .catch((err: unknown) => {
        setNotice(`移交失败：${err instanceof Error ? err.message : String(err)}`);
      })
      .finally(() => setHandingOff(false));
  };

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-sm font-medium">会话台账</h2>
        {hostFilter ? (
          <Button size="sm" variant="ghost" onClick={onClearFilter}>
            清除主机过滤
          </Button>
        ) : null}
        <Button size="sm" variant="outline" className="ml-auto" onClick={onReload} disabled={loading}>
          {loading ? <Loader2Icon className="size-4 animate-spin" /> : <RefreshCwIcon className="size-4" />}
          刷新
        </Button>
      </div>
      {notice ? <p className="text-muted-foreground text-xs">{notice}</p> : null}
      <div className="overflow-x-auto rounded-md border">
        <table className="w-full text-left text-sm">
          <thead className="bg-muted/50 text-muted-foreground">
            <tr>
              <th className="px-3 py-2 font-medium">ID</th>
              <th className="px-3 py-2 font-medium">状态</th>
              <th className="px-3 py-2 font-medium">类型</th>
              <th className="px-3 py-2 font-medium">URL</th>
              <th className="px-3 py-2 font-medium">任务</th>
              <th className="px-3 py-2 font-medium">最近心跳</th>
              <th className="px-3 py-2 font-medium">操作</th>
            </tr>
          </thead>
          <tbody>
            {visible.length === 0 ? (
              <tr>
                <td className="text-muted-foreground px-3 py-6 text-center" colSpan={7}>
                  {loading ? "加载中…" : "暂无会话"}
                </td>
              </tr>
            ) : (
              visible.map((s) => {
                const alive = s.status === "alive";
                return (
                  <tr key={String(s.id)} className="border-t">
                    <td className="px-3 py-2 font-mono">{s.id}</td>
                    <td className="px-3 py-2">
                      <Badge variant={alive ? "default" : "secondary"} className={cn(!alive && "opacity-70")}>
                        {s.status}
                      </Badge>
                    </td>
                    <td className="px-3 py-2">
                      {s.kind}
                      {s.lang ? <span className="text-muted-foreground"> / {s.lang}</span> : null}
                    </td>
                    <td className="max-w-xs truncate px-3 py-2 font-mono text-xs" title={s.url}>
                      {s.url}
                    </td>
                    <td className="px-3 py-2">{s.created_by_task || "—"}</td>
                    <td className="px-3 py-2 whitespace-nowrap">{fmtTime(s.last_beat)}</td>
                    <td className="px-3 py-2">
                      <div className="flex flex-wrap gap-2">
                        <Button size="sm" variant="outline" disabled={probing === String(s.id)} onClick={() => probe(s)}>
                          {probing === String(s.id) ? "探活中…" : "探活"}
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => setHandoffTarget(s)}>
                          移交
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
      <AlertDialog open={handoffTarget !== null} onOpenChange={(o) => !o && !handingOff && setHandoffTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>移交会话 #{handoffTarget?.id} 到内网任务？</AlertDialogTitle>
            <AlertDialogDescription>
              将创建一个新的内网探索任务。初始官方 scope 仅含该立足点主机 /32；发现的新网段进入
              pending_scope 扩容队列（不是出界行动硬闸），批准后写入 task_scope。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={handingOff}>取消</AlertDialogCancel>
            <AlertDialogAction
              disabled={handingOff}
              onClick={(e) => {
                e.preventDefault();
                confirmHandoff();
              }}
            >
              {handingOff ? "创建中…" : "确认移交"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
