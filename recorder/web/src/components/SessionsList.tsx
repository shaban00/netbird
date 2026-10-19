"use client";

import React, { useEffect, useRef, useState } from "react";
import Button from "@components/Button";
import DateRangePicker, { DateRange, isDefaultDateRange, last14Days } from "@components/DateRangePicker";
import Input from "@components/Input";
import Kbd from "@components/Kbd";
import Pagination from "@components/Pagination";
import { Popover, PopoverContent, PopoverTrigger } from "@components/Popover";
import SessionsTable from "@components/SessionsTable";
import StatusFilterPicker from "@components/StatusFilterPicker";
import Tooltip from "@components/Tooltip";
import dayjs from "dayjs";
import { useDebouncedValue } from "@hooks/useDebouncedValue";
import { useSessions } from "@hooks/useSessions";
import { ChevronsUpDownIcon, FilterIcon, FilterXIcon, SearchIcon } from "lucide-react";
import { SessionStatus } from "@utils/types";

const STATUS_LABEL: Record<SessionStatus, string> = {
  recording: "Recording",
  completed: "Completed",
  interrupted: "Interrupted",
  failed: "Failed",
};

const PAGE_SIZE = 10;
const SEARCH_DEBOUNCE_MS = 500;

export default function SessionsList({ onSelect }: { onSelect: (id: string) => void }) {
  const [q, setQ] = useState("");
  const debouncedQ = useDebouncedValue(q, SEARCH_DEBOUNCE_MS);
  const [statuses, setStatuses] = useState<SessionStatus[]>([]);
  const [dateRange, setDateRange] = useState<DateRange>(last14Days);
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [offset, setOffset] = useState(0);
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setOffset(0);
  }, [debouncedQ, statuses, dateRange.from, dateRange.to]);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  const { sessions, total, limit, offset: resolvedOffset, isLoading, error } = useSessions({
    q: debouncedQ || undefined,
    statuses: statuses.length > 0 ? statuses : undefined,
    after: dateRange.from ? dayjs(dateRange.from).toISOString() : undefined,
    before: dateRange.to ? dayjs(dateRange.to).toISOString() : undefined,
    limit: PAGE_SIZE,
    offset,
  });

  const hasActiveFilters = q !== "" || statuses.length > 0 || !isDefaultDateRange(dateRange);
  const resetFilters = () => {
    setQ("");
    setStatuses([]);
    setDateRange(last14Days());
  };
  const removeStatus = (s: SessionStatus) => setStatuses((prev) => prev.filter((x) => x !== s));

  return (
    <div className="px-4 md:px-6 py-6 max-w-7xl mx-auto">
      <h1>{isLoading ? "Session Recordings" : `${total} Session Recording${total === 1 ? "" : "s"}`}</h1>

      <div className="flex flex-wrap gap-2.5 items-center my-5">
        <Input
          ref={searchRef}
          icon={<SearchIcon size={15} />}
          suffix={
            <Kbd>
              <span className="flex items-center gap-0.5">
                Ctrl<span>+</span>K
              </span>
            </Kbd>
          }
          placeholder="Search by hostname, ip, os user..."
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />

        <DateRangePicker value={dateRange} onChange={setDateRange} />

        <Popover open={filtersOpen} onOpenChange={setFiltersOpen}>
          <PopoverTrigger asChild>
            <Button variant="secondary">
              <FilterIcon size={16} className="shrink-0" />
              <span className="flex items-center gap-1.5">
                Filters
                {statuses.length > 0 && (
                  <span className="inline-flex items-center justify-center min-w-4.5 h-4.5 rounded-full bg-netbird text-white text-[10px] font-semibold leading-0! px-1.5">
                    {statuses.length}
                  </span>
                )}
              </span>
              <ChevronsUpDownIcon size={16} className="shrink-0" />
            </Button>
          </PopoverTrigger>
          <PopoverContent className="w-55 p-2" align="start" sideOffset={7}>
            <p className="text-[11px] uppercase tracking-wider text-nb-gray-400 font-medium px-2 pb-1.5">
              Status
            </p>
            <StatusFilterPicker value={statuses} onChange={setStatuses} />
          </PopoverContent>
        </Popover>

        <Tooltip label="Reset filters & search">
          <Button
            variant="secondary"
            size="icon"
            onClick={resetFilters}
            disabled={!hasActiveFilters}
            aria-label="Reset filters & search"
          >
            <FilterXIcon size={16} />
          </Button>
        </Tooltip>
      </div>

      {statuses.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 mb-5 -mt-2.5">
          {statuses.map((s) => (
            <span
              key={s}
              className="inline-flex items-center gap-1.5 text-xs text-nb-gray-300 bg-nb-gray-900 border border-nb-gray-800 rounded-md px-2.5 py-1"
            >
              Status: {STATUS_LABEL[s]}
              <button onClick={() => removeStatus(s)} aria-label={`Remove ${STATUS_LABEL[s]} status filter`} className="text-nb-gray-500 hover:text-white cursor-pointer">
                ×
              </button>
            </span>
          ))}
        </div>
      )}

      {error && <p className="text-red-400">Failed to load sessions: {String(error.message ?? error)}</p>}
      {!error && !isLoading && sessions.length === 0 && (
        <div className="rounded-md border border-nb-gray-900 bg-nb-gray-920 p-10 text-center text-nb-gray-400">
          No recorded sessions match this filter.
        </div>
      )}
      {sessions.length > 0 && (
        <>
          <SessionsTable sessions={sessions} onSelect={onSelect} />
          <Pagination total={total} limit={limit} offset={resolvedOffset} onOffsetChange={setOffset} />
        </>
      )}
    </div>
  );
}
