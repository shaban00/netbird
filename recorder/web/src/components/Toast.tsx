"use client";

import React, { useEffect, useState } from "react";
import { AlertTriangleIcon, CheckIcon, XIcon } from "lucide-react";
import { cn } from "@utils/helpers";

type ToastMessage = {
  id: number;
  title: string;
  description?: string;
  variant?: "success" | "error";
  leaving?: boolean;
};

type Listener = (toasts: ToastMessage[]) => void;

let toasts: ToastMessage[] = [];
let listeners: Listener[] = [];
let nextId = 0;

const leaveDurationMs = 150;

function emit() {
  listeners.forEach((l) => l(toasts));
}

function remove(id: number) {
  toasts = toasts.filter((t) => t.id !== id);
  emit();
}

function dismiss(id: number) {
  toasts = toasts.map((t) => (t.id === id ? { ...t, leaving: true } : t));
  emit();
  window.setTimeout(() => remove(id), leaveDurationMs);
}

export function showToast(
  toast: { title: string; description?: string; variant?: "success" | "error" },
  durationMs = 3000,
) {
  const id = nextId++;
  toasts = [...toasts, { id, ...toast }];
  emit();
  window.setTimeout(() => dismiss(id), durationMs);
}

export default function Toaster() {
  const [items, setItems] = useState<ToastMessage[]>(toasts);

  useEffect(() => {
    listeners.push(setItems);
    return () => {
      listeners = listeners.filter((l) => l !== setItems);
    };
  }, []);

  if (items.length === 0) return null;

  return (
    <div className="fixed top-3 left-1/2 -translate-x-1/2 z-100 flex flex-col gap-2 w-[min(28rem,calc(100vw-2rem))]">
      {items.map((t) => (
        <div
          key={t.id}
          role="status"
          className={cn(
            "flex items-center justify-between gap-4 rounded-md border border-nb-gray-900 bg-nb-gray-940 shadow-lg px-4 py-2.5",
            t.leaving ? "animate-toast-out" : "animate-toast-in",
          )}
        >
          <div className="flex items-center gap-4 min-w-0">
            <span
              className={cn(
                "flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-white shadow-sm",
                t.variant === "error" ? "bg-red-500" : "bg-green-500",
              )}
            >
              {t.variant === "error" ? <AlertTriangleIcon size={14} /> : <CheckIcon size={14} />}
            </span>
            <div className="flex flex-col text-sm min-w-0">
              <p className="font-semibold text-gray-100">{t.title}</p>
              {t.description && <p className="text-xs text-nb-gray-300 mt-0.5">{t.description}</p>}
            </div>
          </div>
          <button
            type="button"
            onClick={() => dismiss(t.id)}
            aria-label="Dismiss notification"
            className="group flex items-center cursor-pointer shrink-0"
          >
            <span className="p-2 rounded-md opacity-50 group-hover:opacity-100 group-hover:bg-nb-gray-900 transition-colors">
              <XIcon size={16} />
            </span>
          </button>
        </div>
      ))}
    </div>
  );
}
