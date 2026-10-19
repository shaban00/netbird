import React from "react";
import { cn } from "@utils/helpers";

export default function Kbd({
  children,
  className,
}: Readonly<{ children: React.ReactNode; className?: string }>) {
  return (
    <div
      className={cn(
        "shadow-xs border rounded-sm leading-0 flex gap-1 items-center",
        "bg-nb-gray-800 border-nb-gray-700 text-nb-gray-300",
        "py-2.5 px-1.5 text-xs h-3",
        className,
      )}
    >
      {children}
    </div>
  );
}
