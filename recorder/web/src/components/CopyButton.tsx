"use client";

import React, { useState } from "react";
import { showToast } from "@components/Toast";
import { CheckIcon, CopyIcon } from "lucide-react";
import { cn, copyToClipboard } from "@utils/helpers";

export default function CopyButton({
  value,
  label,
  className,
}: {
  value: string;
  label: string;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);

  const onCopy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!value) return;
    const ok = await copyToClipboard(value);
    if (!ok) {
      showToast({
        title: "Copy failed",
        description: `Couldn't copy ${label.toLowerCase()} — select and copy it manually.`,
        variant: "error",
      });
      return;
    }
    setCopied(true);
    showToast({ title: "Copied to clipboard", description: `${label} has been copied to clipboard.` });
    window.setTimeout(() => setCopied(false), 1500);
  };

  return (
    <button
      type="button"
      onClick={onCopy}
      aria-label={`Copy ${label}`}
      className={cn(
        "shrink-0 cursor-pointer rounded-sm p-0.5 text-nb-gray-500 hover:text-white transition-colors",
        className,
      )}
    >
      {copied ? <CheckIcon size={13} className="text-green-500" /> : <CopyIcon size={13} />}
    </button>
  );
}
