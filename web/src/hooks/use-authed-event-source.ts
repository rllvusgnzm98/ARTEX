"use client";

import * as React from "react";

import { refresh } from "@/lib/auth";
import { sseUrl } from "@/lib/api";

type Listener = (ev: MessageEvent, es: EventSource) => void;

export type AuthedEventSourceHandlers = {
  onopen?: (ev: Event) => void;
  onmessage?: (ev: MessageEvent) => void;
  onerror?: (ev: Event) => void;
  listeners?: Record<string, Listener>;
};

// useAuthedEventSource 打开一条带当前令牌的 SSE。onerror 时先单飞刷新，再重建连接；
// 重建后的连接若在 onopen 之前再次出错，则交给浏览器自己的重连，避免打转。
// path 为空时不连接。depsKey 变化会拆掉旧连接再建一条（path 本身已经在依赖里）。
export function useAuthedEventSource(
  path: string | null,
  handlers: AuthedEventSourceHandlers,
  depsKey?: unknown,
) {
  const handlersRef = React.useRef(handlers);
  handlersRef.current = handlers;

  React.useEffect(() => {
    if (!path) return;
    let alive = true;
    let es: EventSource | null = null;
    let armed = true;

    const open = () => {
      es?.close();
      const next = new EventSource(sseUrl(path));
      es = next;
      next.onopen = (ev) => {
        armed = true;
        handlersRef.current.onopen?.(ev);
      };
      next.onmessage = (ev) => handlersRef.current.onmessage?.(ev);
      const names = Object.keys(handlersRef.current.listeners ?? {});
      for (const name of names) {
        next.addEventListener(name, (ev) => {
          handlersRef.current.listeners?.[name]?.(ev as MessageEvent, next);
        });
      }
      next.onerror = (ev) => {
        handlersRef.current.onerror?.(ev);
        if (!alive || !armed) return;
        armed = false;
        next.close();
        void refresh().finally(() => {
          if (alive) open();
        });
      };
    };

    open();
    return () => {
      alive = false;
      es?.close();
      es = null;
    };
  }, [path, depsKey]);
}
