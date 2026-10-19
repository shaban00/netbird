import { cn } from "@utils/helpers";
import React from "react";

type Props = { children: React.ReactNode; className?: string };

export default function PageContainer({ children, className }: Readonly<Props>) {
  return (
    <div className={cn(className, "relative flex-auto bg-nb-gray min-h-screen")}>
      {children}
    </div>
  );
}
