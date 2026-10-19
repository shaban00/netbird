import React from "react";
import { cn } from "@utils/helpers";
import { CheckIcon } from "lucide-react";
import { SessionStatus } from "@utils/types";

const OPTIONS: { value: SessionStatus; label: string }[] = [
  { value: "recording", label: "Recording" },
  { value: "completed", label: "Completed" },
  { value: "interrupted", label: "Interrupted" },
  { value: "failed", label: "Failed" },
];

export default function StatusFilterPicker({
  value,
  onChange,
}: {
  value: SessionStatus[];
  onChange: (next: SessionStatus[]) => void;
}) {
  const toggle = (status: SessionStatus) => {
    if (value.includes(status)) {
      onChange(value.filter((s) => s !== status));
    } else {
      onChange([...value, status]);
    }
  };

  return (
    <div className="flex flex-col gap-0.5">
      {OPTIONS.map((option) => {
        const selected = value.includes(option.value);
        return (
          <div
            key={option.value}
            role="button"
            tabIndex={0}
            className={cn(
              "flex items-center gap-2.5 px-2 py-1.5 rounded-sm text-sm transition-colors cursor-pointer",
              "text-nb-gray-300 hover:bg-nb-gray-900 hover:text-white",
              selected && "text-white",
            )}
            onClick={() => toggle(option.value)}
          >
            <span className="h-3.5 w-3.5 shrink-0 flex items-center justify-center rounded-sm border border-nb-gray-700 bg-nb-gray-900">
              {selected && <CheckIcon size={11} className="text-netbird" />}
            </span>
            {option.label}
          </div>
        );
      })}
    </div>
  );
}
