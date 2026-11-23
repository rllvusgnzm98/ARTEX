"use client";

import * as React from "react";

import { GemIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { Asset } from "@/lib/types";

// CrownJewelToggle marks/unmarks an asset as a crown jewel (目标导向分析) and edits
// its business-value note; the planner prioritizes intents approaching marked targets.
export function CrownJewelToggle({ asset, onChange }: { asset: Asset; onChange?: () => void }) {
  const [open, setOpen] = React.useState(false);
  const [note, setNote] = React.useState(asset.crown_jewel_note ?? "");
  const [saving, setSaving] = React.useState(false);
  const on = !!asset.crown_jewel;

  React.useEffect(() => {
    setNote(asset.crown_jewel_note ?? "");
  }, [asset.crown_jewel_note]);

  async function mark() {
    setSaving(true);
    try {
      await api.setCrownJewel(asset.id, note.trim());
      toast.success("已标记为靶标");
      setOpen(false);
      onChange?.();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "标记失败");
    } finally {
      setSaving(false);
    }
  }

  async function unmark() {
    setSaving(true);
    try {
      await api.unsetCrownJewel(asset.id);
      toast.success("已取消靶标");
      setOpen(false);
      onChange?.();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "取消失败");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className={`size-7 ${on ? "text-amber-500 hover:text-amber-600" : "text-muted-foreground hover:text-amber-500"}`}
          aria-label={on ? "靶标资产，点击编辑" : "标记为靶标"}
        >
          <GemIcon className="size-3.5" fill={on ? "currentColor" : "none"} />
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-72 space-y-2">
        <div className="text-sm font-medium">{on ? "靶标资产 (Crown Jewel)" : "标记为靶标 (Crown Jewel)"}</div>
        <p className="text-xs text-muted-foreground">标记高价值目标资产，规划器会优先派逼近它的意图。</p>
        <Textarea
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder="业务价值说明（可选）"
          className="min-h-16 text-xs"
        />
        <div className="flex justify-end gap-2">
          {on && (
            <Button variant="outline" size="sm" disabled={saving} onClick={unmark}>
              取消靶标
            </Button>
          )}
          <Button size="sm" disabled={saving} onClick={mark}>
            {on ? "保存" : "标记"}
          </Button>
        </div>
      </PopoverContent>
    </Popover>
  );
}
