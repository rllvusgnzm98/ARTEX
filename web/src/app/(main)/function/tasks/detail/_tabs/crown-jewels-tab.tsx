"use client";

import * as React from "react";

import { ChevronRightIcon, GemIcon, RefreshCwIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Spinner } from "@/components/ui/spinner";
import { api } from "@/lib/api";
import type { Asset, CrownJewelStatus, CrownJewelTarget } from "@/lib/types";

// 靶标路径 (Crown Jewels): per-target situational standing for this task — reached?
// how close is the exploration frontier? and the attack-path lineage (root→…→reaching
// node) retraced along the exploration graph (derived_from/yields/spawns).
function assetLabel(a: Asset): string {
  for (const part of [a.url, a.domain, a.ip, a.app_name]) {
    if (part) return part;
  }
  return `#${a.id}`;
}

function ReachBadge({ status }: { status: CrownJewelStatus }) {
  if (status.reached_by_finding) {
    return <Badge className="bg-emerald-600 hover:bg-emerald-600">已被发现触达</Badge>;
  }
  if (status.reached_by_fact) {
    return <Badge variant="secondary">已被事实触达</Badge>;
  }
  return (
    <Badge variant="outline" className="text-muted-foreground">
      尚未触达
    </Badge>
  );
}

export function CrownJewelsTab({ taskId }: { taskId: string }) {
  const [targets, setTargets] = React.useState<CrownJewelTarget[]>([]);
  const [loading, setLoading] = React.useState(true);

  const load = React.useCallback(() => {
    setLoading(true);
    api
      .crownJewelPaths(taskId)
      .then((r) => setTargets(r.targets))
      .catch((e) => toast.error(e instanceof Error ? e.message : "加载失败"))
      .finally(() => setLoading(false));
  }, [taskId]);

  React.useEffect(() => {
    load();
  }, [load]);

  if (loading && targets.length === 0) {
    return (
      <div className="flex items-center justify-center py-16 text-muted-foreground">
        <Spinner className="size-5" />
      </div>
    );
  }

  if (targets.length === 0) {
    return (
      <Card className="p-8 text-center text-sm text-muted-foreground">
        还没有标记靶标资产。在「资产」页面点击 <GemIcon className="inline size-3.5" /> 把高价值资产标记为靶标 (Crown
        Jewel)，规划器会优先派逼近它的意图。
      </Card>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          共 {targets.length} 个靶标。距离越小表示当前探索前沿越接近靶标；无距离表示尚无任何节点触达。
        </p>
        <Button variant="outline" size="sm" onClick={load} disabled={loading}>
          <RefreshCwIcon className="size-3.5" /> 刷新
        </Button>
      </div>
      {targets.map((t) => {
        const s = t.status;
        return (
          <Card key={t.asset.id} className="space-y-3 p-4">
            <div className="flex flex-wrap items-center gap-2">
              <GemIcon className="size-4 text-amber-500" fill="currentColor" />
              <span className="font-mono text-sm font-medium">{assetLabel(t.asset)}</span>
              <ReachBadge status={s} />
              {s.frontier_distance != null ? (
                <Badge variant="outline">前沿距离 {s.frontier_distance}</Badge>
              ) : (
                <Badge variant="outline" className="text-muted-foreground">
                  前沿距离 ∞
                </Badge>
              )}
              {t.goal_ids?.length ? <Badge variant="outline">锚定 {t.goal_ids.length} 个目标</Badge> : null}
            </div>
            {t.asset.crown_jewel_note ? (
              <p className="text-xs text-muted-foreground">业务价值：{t.asset.crown_jewel_note}</p>
            ) : null}
            {s.path?.length ? (
              <div className="space-y-1">
                <div className="text-xs font-medium text-muted-foreground">攻击路径（根 → 触达节点）</div>
                <div className="flex flex-wrap items-center gap-1">
                  {s.path.map((n, i) => (
                    <React.Fragment key={n.id}>
                      {i > 0 && <ChevronRightIcon className="size-3 text-muted-foreground" />}
                      <Badge variant="secondary" className="font-normal" title={n.summary}>
                        <span className="text-muted-foreground">{n.kind}</span>
                        <span className="ml-1 max-w-48 truncate">{n.summary || `#${n.id}`}</span>
                      </Badge>
                    </React.Fragment>
                  ))}
                </div>
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">还没有到达该靶标的攻击路径。</p>
            )}
          </Card>
        );
      })}
    </div>
  );
}
