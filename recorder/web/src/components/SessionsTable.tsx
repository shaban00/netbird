"use client";

import React from "react";
import CopyButton from "@components/CopyButton";
import StatusBadge from "@components/StatusBadge";
import { ArrowUpDownIcon, ClockIcon, LogInIcon, MonitorIcon } from "lucide-react";
import { duration, fmtDate, timeAgo } from "@utils/date";
import { Session } from "@utils/types";

type Props = {
  sessions: Session[];
  onSelect: (id: string) => void;
};

export default function SessionsTable({ sessions, onSelect }: Props) {
  return (
    <>
      <div className="hidden md:block rounded-md border border-nb-gray-900 overflow-hidden">
        <table className="w-full border-collapse table-fixed">
          <thead className="bg-nb-gray-900/60">
            <tr>
              <Th className="w-[22%]">From</Th>
              <Th className="w-[22%]">Peer</Th>
              <Th className="w-[10%]">OS User</Th>
              <Th className="w-[16%]">Last activity</Th>
              <Th className="w-[10%]">Duration</Th>
              <Th className="w-[18%]">Status</Th>
            </tr>
          </thead>
          <tbody>
            {sessions.map((s) => (
              <tr
                key={s.id}
                onClick={() => onSelect(s.id)}
                className="border-t border-nb-gray-900 hover:bg-netbird-950/10 cursor-pointer transition-colors"
              >
                <td className="px-4 py-4">
                  <div className="flex items-center gap-2.5">
                    <LogInIcon size={15} className="text-nb-gray-400 shrink-0" />
                    <div className="flex flex-col gap-0.5 min-w-0">
                      <span className="flex items-center gap-1.5 min-w-0">
                        <span className="text-gray-100 font-medium text-sm truncate min-w-0">
                          {s.source_peer_name || s.source_peer_id || "Unknown"}
                        </span>
                        {(s.source_peer_name || s.source_peer_id) && (
                          <CopyButton value={s.source_peer_name || s.source_peer_id} label="From hostname" />
                        )}
                      </span>
                      <span className="flex items-center gap-1.5 min-w-0">
                        <span className="text-nb-gray-400 text-xs truncate min-w-0">{s.source_peer_ip}</span>
                        {s.source_peer_ip && <CopyButton value={s.source_peer_ip} label="From IP address" />}
                      </span>
                    </div>
                  </div>
                </td>
                <td className="px-4 py-4">
                  <div className="flex items-center gap-2.5">
                    <MonitorIcon size={15} className="text-nb-gray-400 shrink-0" />
                    <div className="flex flex-col gap-0.5 min-w-0">
                      <span className="flex items-center gap-1.5 min-w-0">
                        <span className="text-gray-100 font-medium text-sm truncate min-w-0">
                          {s.peer_name || s.peer_id}
                        </span>
                        <CopyButton value={s.peer_name || s.peer_id} label="Peer hostname" />
                      </span>
                      <span className="flex items-center gap-1.5 min-w-0">
                        <span className="text-nb-gray-400 text-xs truncate min-w-0">{s.peer_ip}</span>
                        {s.peer_ip && <CopyButton value={s.peer_ip} label="Peer IP address" />}
                      </span>
                    </div>
                  </div>
                </td>
                <td className="px-4 py-4 text-sm text-gray-200">
                  <span className="flex items-center gap-1.5 min-w-0">
                    <span className="truncate min-w-0">{s.os_username}</span>
                    {s.os_username && <CopyButton value={s.os_username} label="OS user" />}
                  </span>
                </td>
                <td className="px-4 py-4">
                  <div
                    className="flex items-center gap-2 text-sm text-gray-200"
                    title={fmtDate(s.started_at)}
                  >
                    <ClockIcon size={14} className="text-nb-gray-400" />
                    {timeAgo(s.started_at)}
                  </div>
                </td>
                <td className="px-4 py-4 text-sm text-gray-200">
                  {duration(s.started_at, s.ended_at)}
                </td>
                <td className="px-4 py-4">
                  <StatusBadge status={s.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="md:hidden flex flex-col gap-3">
        {sessions.map((s) => (
          <div
            key={s.id}
            onClick={() => onSelect(s.id)}
            role="button"
            tabIndex={0}
            className="rounded-md border border-nb-gray-900 bg-nb-gray-920 p-4 cursor-pointer active:bg-netbird-950/10 transition-colors"
          >
            <div className="flex items-center justify-between gap-2 mb-3">
              <StatusBadge status={s.status} />
              <div
                className="flex items-center gap-1.5 text-xs text-nb-gray-400 shrink-0"
                title={fmtDate(s.started_at)}
              >
                <ClockIcon size={13} />
                {timeAgo(s.started_at)}
              </div>
            </div>

            <div className="flex items-center gap-2.5 mb-2.5">
              <LogInIcon size={15} className="text-nb-gray-400 shrink-0" />
              <div className="flex flex-col gap-0.5 min-w-0">
                <span className="flex items-center gap-1.5 min-w-0">
                  <span className="text-gray-100 font-medium text-sm truncate min-w-0">
                    {s.source_peer_name || s.source_peer_id || "Unknown"}
                  </span>
                  {(s.source_peer_name || s.source_peer_id) && (
                    <CopyButton value={s.source_peer_name || s.source_peer_id} label="From hostname" />
                  )}
                </span>
                <span className="flex items-center gap-1.5 min-w-0">
                  <span className="text-nb-gray-400 text-xs truncate min-w-0">{s.source_peer_ip}</span>
                  {s.source_peer_ip && <CopyButton value={s.source_peer_ip} label="From IP address" />}
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2.5 mb-3">
              <MonitorIcon size={15} className="text-nb-gray-400 shrink-0" />
              <div className="flex flex-col gap-0.5 min-w-0">
                <span className="flex items-center gap-1.5 min-w-0">
                  <span className="text-gray-100 font-medium text-sm truncate min-w-0">
                    {s.peer_name || s.peer_id}
                  </span>
                  <CopyButton value={s.peer_name || s.peer_id} label="Peer hostname" />
                </span>
                <span className="flex items-center gap-1.5 min-w-0">
                  <span className="text-nb-gray-400 text-xs truncate min-w-0">{s.peer_ip}</span>
                  {s.peer_ip && <CopyButton value={s.peer_ip} label="Peer IP address" />}
                </span>
              </div>
            </div>

            <div className="flex items-center justify-between text-xs text-nb-gray-400 pt-2.5 border-t border-nb-gray-900">
              <span className="flex items-center gap-1.5 min-w-0">
                <span className="truncate min-w-0">{s.os_username}</span>
                {s.os_username && <CopyButton value={s.os_username} label="OS user" />}
              </span>
              <span className="shrink-0">{duration(s.started_at, s.ended_at)}</span>
            </div>
          </div>
        ))}
      </div>
    </>
  );
}

function Th({ children, className = "" }: { children?: React.ReactNode; className?: string }) {
  return (
    <th className={`text-left px-4 py-3.5 ${className}`}>
      {children && (
        <span className="inline-flex items-center gap-1.5 text-[11px] uppercase tracking-wider text-nb-gray-400 font-medium">
          {children}
          <ArrowUpDownIcon size={12} className="opacity-60" />
        </span>
      )}
    </th>
  );
}
