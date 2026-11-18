"use client";

import * as React from "react";

import { Loader2Icon, RefreshCwIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type { IntranetTopology, ShellSession, Task } from "@/lib/types";

import { type HostFilter, SessionsTab } from "./_components/sessions-tab";
import { PendingScopeTab } from "./_components/pending-scope-tab";
import { TopologyGraph } from "./_components/topology-graph";

export default function IntranetPage() {
  const [topology, setTopology] = React.useState<IntranetTopology | null>(null);
  const [sessions, setSessions] = React.useState<ShellSession[]>([]);
  const [loadingTopology, setLoadingTopology] = React.useState(true);
  const [loadingSessions, setLoadingSessions] = React.useState(true);
  const [hostFilter, setHostFilter] = React.useState<HostFilter | null>(null);
  const [taskId, setTaskId] = React.useState("all");
  const [tasks, setTasks] = React.useState<Task[]>([]);
  const taskParam = taskId === "all" ? undefined : taskId;

  React.useEffect(() => {
    api
      .tasks()
      .then((r) => setTasks(r.tasks))
      .catch(() => {
        /* 任务列表拉取失败不阻塞台账 */
      });
  }, []);

  const loadTopology = React.useCallback(() => {
    setLoadingTopology(true);
    api
      .intranetTopology(taskParam)
      .then(setTopology)
      .catch(() => {
        /* 保留上一次数据 */
      })
      .finally(() => setLoadingTopology(false));
  }, [taskParam]);

  const sigRef = React.useRef("");
  const loadSessions = React.useCallback(
    (initial = false) => {
      if (initial) setLoadingSessions(true);
      api
        .shellSessions(taskParam)
        .then((items) => {
          const sig = JSON.stringify(items);
          if (sig !== sigRef.current) {
            sigRef.current = sig;
            setSessions(items);
          }
        })
        .catch(() => {
          /* 保留上一次数据 */
        })
        .finally(() => initial && setLoadingSessions(false));
    },
    [taskParam],
  );

  React.useEffect(() => {
    loadTopology();
    loadSessions(true);
  }, [loadTopology, loadSessions]);

  return (
    <div className="flex h-full min-h-0 flex-col gap-4 p-4">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-lg font-semibold">内网</h1>
        <Select value={taskId} onValueChange={setTaskId}>
          <SelectTrigger className="w-64">
            <SelectValue placeholder="全部任务" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部任务</SelectItem>
            {tasks.map((task) => (
              <SelectItem key={task.id} value={String(task.id)}>
                {task.name || task.description || `任务 ${task.id}`}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button
          size="sm"
          variant="outline"
          className="ml-auto"
          onClick={() => {
            loadTopology();
            loadSessions(true);
          }}
        >
          {loadingTopology || loadingSessions ? (
            <Loader2Icon className="size-4 animate-spin" />
          ) : (
            <RefreshCwIcon className="size-4" />
          )}
          刷新
        </Button>
      </div>

      <div className="min-h-[280px] flex-1 rounded-md border">
        <TopologyGraph
          data={topology}
          loading={loadingTopology}
          onRefresh={loadTopology}
          onSelectHost={(nodeId) => setHostFilter({ id: nodeId })}
        />
      </div>

      <Tabs defaultValue="sessions" className="flex min-h-0 flex-1 flex-col">
        <TabsList>
          <TabsTrigger value="sessions">会话</TabsTrigger>
          <TabsTrigger value="pending">待授权网段</TabsTrigger>
        </TabsList>
        <TabsContent value="sessions" className="flex-1 overflow-auto">
          <SessionsTab
            sessions={sessions}
            loading={loadingSessions}
            onReload={() => loadSessions(true)}
            hostFilter={hostFilter}
            onClearFilter={() => setHostFilter(null)}
          />
        </TabsContent>
        <TabsContent value="pending" className="flex-1 overflow-auto">
          <PendingScopeTab taskId={taskParam} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
