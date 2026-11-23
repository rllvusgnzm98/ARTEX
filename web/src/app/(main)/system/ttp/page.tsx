"use client";

import * as React from "react";

import { BookOpenCheckIcon, CheckIcon, RefreshCwIcon, UploadIcon, XIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { TTPEntry } from "@/lib/types";

// 决策知识审核 (TTP): 任务收官自动复盘 + 外部 writeup 导入都先入库待审(pending),
// 人工通过后才并入 agent/chainskel 决策语料。来源(retro/writeup)与置信度明确区分,
// 避免低质量外部内容污染语料。
const STATUS_LABEL: Record<string, string> = { pending: "待审", approved: "已通过", rejected: "已拒绝" };

function sourceBadge(source: string) {
  return source === "retro" ? (
    <Badge className="bg-sky-600 hover:bg-sky-600">任务复盘</Badge>
  ) : (
    <Badge className="bg-violet-600 hover:bg-violet-600">外部 writeup</Badge>
  );
}

export default function TTPReviewPage() {
  const [entries, setEntries] = React.useState<TTPEntry[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [status, setStatus] = React.useState("pending");
  const [text, setText] = React.useState("");
  const [originRef, setOriginRef] = React.useState("");
  const [importing, setImporting] = React.useState(false);
  const [busyId, setBusyId] = React.useState<number | null>(null);
  const fileRef = React.useRef<HTMLInputElement>(null);

  const load = React.useCallback((s: string) => {
    setLoading(true);
    api
      .ttpEntries(s === "all" ? undefined : s)
      .then((r) => setEntries(r.entries))
      .catch((e) => toast.error(e instanceof Error ? e.message : "加载失败"))
      .finally(() => setLoading(false));
  }, []);

  React.useEffect(() => {
    load(status);
  }, [load, status]);

  async function review(id: number, approve: boolean) {
    setBusyId(id);
    try {
      await (approve ? api.approveTTP(id) : api.rejectTTP(id));
      toast.success(approve ? "已通过并入决策语料" : "已拒绝");
      load(status);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "操作失败");
    } finally {
      setBusyId(null);
    }
  }

  async function submitWriteup() {
    if (!text.trim()) {
      toast.error("请粘贴或上传 writeup 文本");
      return;
    }
    setImporting(true);
    try {
      const r = await api.importWriteup(text.trim(), originRef.trim());
      toast.success(`已解析入队 ${r.queued} 条待审 TTP`);
      setText("");
      setOriginRef("");
      setStatus("pending");
      load("pending");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "导入失败");
    } finally {
      setImporting(false);
    }
  }

  function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    file
      .text()
      .then((content) => {
        setText(content);
        if (!originRef.trim()) setOriginRef(file.name);
      })
      .catch(() => toast.error("读取文件失败"));
    e.target.value = "";
  }

  return (
    <div className="flex flex-col gap-4 p-4">
      <div className="flex items-center gap-2">
        <BookOpenCheckIcon className="size-5 text-primary" />
        <h1 className="text-lg font-semibold">决策知识审核 (TTP)</h1>
      </div>
      <p className="text-sm text-muted-foreground">
        任务收官会自动复盘生成"场景→判据→转向"条目;也可在下方导入外部 writeup。两类产出都先入库待审,
        <span className="font-medium">人工通过后才并入 agent/chainskel 决策语料</span>。
      </p>

      <Card className="space-y-2 p-4">
        <div className="flex items-center gap-2 text-sm font-medium">
          <UploadIcon className="size-4" /> 导入外部 writeup
        </div>
        <Textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="粘贴 writeup / 漏洞报告原文,或点右侧上传文本文件"
          className="min-h-32 text-xs"
        />
        <div className="flex flex-wrap items-center gap-2">
          <Input
            value={originRef}
            onChange={(e) => setOriginRef(e.target.value)}
            placeholder="来源标注(URL/标题,可选)"
            className="h-8 max-w-80 text-xs"
          />
          <input ref={fileRef} type="file" accept=".txt,.md,text/*" className="hidden" onChange={onFile} />
          <Button variant="outline" size="sm" onClick={() => fileRef.current?.click()} disabled={importing}>
            <UploadIcon className="size-3.5" /> 上传文件
          </Button>
          <Button size="sm" onClick={submitWriteup} disabled={importing}>
            {importing ? <Spinner className="size-3.5" /> : null} 解析入队
          </Button>
        </div>
      </Card>

      <div className="flex items-center justify-between">
        <Tabs value={status} onValueChange={setStatus}>
          <TabsList>
            <TabsTrigger value="pending">待审</TabsTrigger>
            <TabsTrigger value="approved">已通过</TabsTrigger>
            <TabsTrigger value="rejected">已拒绝</TabsTrigger>
            <TabsTrigger value="all">全部</TabsTrigger>
          </TabsList>
        </Tabs>
        <Button variant="outline" size="sm" onClick={() => load(status)} disabled={loading}>
          <RefreshCwIcon className="size-3.5" /> 刷新
        </Button>
      </div>

      {loading && entries.length === 0 && (
        <div className="flex items-center justify-center py-16 text-muted-foreground">
          <Spinner className="size-5" />
        </div>
      )}
      {!loading && entries.length === 0 && (
        <Card className="p-8 text-center text-sm text-muted-foreground">该状态下暂无条目。</Card>
      )}
      {entries.length > 0 && (
        <div className="space-y-3">
          {entries.map((e) => (
            <Card key={e.id} className="space-y-2 p-4">
              <div className="flex flex-wrap items-center gap-2">
                {sourceBadge(e.source)}
                <Badge variant="outline">{e.category}</Badge>
                {e.source === "writeup" ? (
                  <Badge variant="outline" className="text-muted-foreground">
                    置信度 {Math.round((e.confidence ?? 0) * 100)}%
                  </Badge>
                ) : null}
                {e.task_id ? (
                  <Badge variant="outline" className="text-muted-foreground">
                    来源任务 #{e.task_id}
                  </Badge>
                ) : null}
                {e.origin_ref ? <span className="text-xs text-muted-foreground">来源：{e.origin_ref}</span> : null}
                <Badge variant="secondary" className="ml-auto">
                  {STATUS_LABEL[e.status] ?? e.status}
                </Badge>
              </div>
              <div className="space-y-1 text-sm">
                <div>
                  <span className="text-muted-foreground">场景：</span>
                  {e.scene}
                </div>
                <div>
                  <span className="text-muted-foreground">判据：</span>
                  {e.criteria}
                </div>
                <div>
                  <span className="text-muted-foreground">转向：</span>
                  {e.pivot}
                </div>
              </div>
              {e.status === "pending" ? (
                <div className="flex justify-end gap-2">
                  <Button variant="outline" size="sm" disabled={busyId === e.id} onClick={() => review(e.id, false)}>
                    <XIcon className="size-3.5" /> 拒绝
                  </Button>
                  <Button size="sm" disabled={busyId === e.id} onClick={() => review(e.id, true)}>
                    <CheckIcon className="size-3.5" /> 通过
                  </Button>
                </div>
              ) : null}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
