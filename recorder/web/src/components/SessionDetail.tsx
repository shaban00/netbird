"use client";

import React from "react";
import CopyButton from "@components/CopyButton";
import StatusBadge from "@components/StatusBadge";
import { useSession } from "@hooks/useSession";
import { ArrowLeftIcon } from "lucide-react";
import dynamic from "next/dynamic";
import { duration, fmtDate } from "@utils/date";

const CastPlayer = dynamic(() => import("@components/CastPlayer"), { ssr: false });

export default function SessionDetail({
  id,
  onBack,
}: {
  id: string;
  onBack: () => void;
}) {
  const { session, isLoading, error, refresh } = useSession(id);

  return (
    <div className="px-4 md:px-6 py-6 max-w-7xl mx-auto">
      <button
        onClick={onBack}
        className="inline-flex items-center gap-2 text-sm text-nb-gray-400 hover:text-white mb-6 cursor-pointer"
      >
        <ArrowLeftIcon size={14} />
        Back to sessions
      </button>

      {isLoading && <p className="text-nb-gray-400">Loading…</p>}
      {error && <p className="text-red-400">Failed to load session: {String(error.message ?? error)}</p>}

      {session && (
        <>
          <div className="flex flex-col gap-5 rounded-md border border-nb-gray-900 bg-nb-gray-920 p-5 mb-5">
            <dl className="grid grid-cols-2 sm:grid-cols-3 gap-5">
              <HostField
                label="From"
                name={session.source_peer_name || session.source_peer_id || "Unknown"}
                nameCopyLabel={session.source_peer_name || session.source_peer_id ? "From hostname" : undefined}
                ip={session.source_peer_ip}
                ipCopyLabel="From IP address"
              />
              <HostField
                label="Peer"
                name={session.peer_name || session.peer_id}
                nameCopyLabel="Peer hostname"
                ip={session.peer_ip}
                ipCopyLabel="Peer IP address"
              />
              <Field
                label="User ID hash"
                value={session.user_id_hash || "No SSO identity (JWT auth not used)"}
                copyLabel={session.user_id_hash ? "User ID hash" : undefined}
              />
            </dl>
            <dl className="grid grid-cols-2 sm:grid-cols-4 gap-5">
              <Field label="OS user" value={session.os_username} copyLabel="OS user" />
              <Field label="Started" value={fmtDate(session.started_at)} />
              <Field label="Duration" value={duration(session.started_at, session.ended_at)} />
              <div className="min-w-0">
                <dt className="text-[11px] uppercase tracking-wider text-nb-gray-400 mb-1.5">
                  Status
                </dt>
                <dd>
                  <StatusBadge status={session.status} />
                </dd>
              </div>
            </dl>
          </div>

          {session.status === "recording" && (
            <CastPlayer src={liveSessionURL(session.id)} live onEnded={refresh} />
          )}
          {session.status === "failed" && (
            <EmptyState text="Recording failed before any output was captured." className="text-red-400" />
          )}
          {session.status !== "recording" && session.status !== "failed" && (
            <CastPlayer src={`/api/sessions/${encodeURIComponent(session.id)}/recording`} />
          )}
        </>
      )}
    </div>
  );
}

function liveSessionURL(id: string): string {
  if (typeof window === "undefined") return "";
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${window.location.host}/api/sessions/${encodeURIComponent(id)}/live`;
}

function Field({
  label,
  value,
  copyLabel,
}: {
  label: string;
  value: string;
  copyLabel?: string;
}) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] uppercase tracking-wider text-nb-gray-400 mb-1.5">{label}</dt>
      <dd className="flex items-start gap-1.5 min-w-0">
        <span className="text-sm text-gray-100 break-all min-w-0" title={value}>
          {value}
        </span>
        {copyLabel && <CopyButton value={value} label={copyLabel} />}
      </dd>
    </div>
  );
}

function HostField({
  label,
  name,
  nameCopyLabel,
  ip,
  ipCopyLabel,
}: {
  label: string;
  name: string;
  nameCopyLabel?: string;
  ip: string;
  ipCopyLabel: string;
}) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] uppercase tracking-wider text-nb-gray-400 mb-1.5">{label}</dt>
      <dd className="flex items-start gap-1.5 min-w-0">
        <span className="text-sm text-gray-100 break-all min-w-0" title={name}>
          {name}
        </span>
        {nameCopyLabel && <CopyButton value={name} label={nameCopyLabel} />}
      </dd>
      {ip && (
        <dd className="flex items-start gap-1.5 min-w-0 mt-0.5">
          <span className="text-xs text-nb-gray-400 break-all min-w-0" title={ip}>
            {ip}
          </span>
          <CopyButton value={ip} label={ipCopyLabel} />
        </dd>
      )}
    </div>
  );
}

function EmptyState({ text, className = "" }: { text: string; className?: string }) {
  return (
    <div
      className={`rounded-md border border-nb-gray-900 bg-nb-gray-920 p-10 text-center text-nb-gray-400 ${className}`}
    >
      {text}
    </div>
  );
}
