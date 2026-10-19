import React from "react";
import Badge, { BadgeVariants } from "@components/Badge";
import { SessionStatus } from "@utils/types";

const VARIANT_BY_STATUS: Record<SessionStatus, NonNullable<BadgeVariants["variant"]>> = {
  completed: "green",
  recording: "blue",
  interrupted: "yellow",
  failed: "red",
};

export default function StatusBadge({ status }: { status: SessionStatus }) {
  return (
    <Badge variant={VARIANT_BY_STATUS[status] ?? "gray"} size="xs">
      {status}
    </Badge>
  );
}
