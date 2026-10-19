"use client";

import React, { useState } from "react";
import Button from "@components/Button";
import { Popover, PopoverContent, PopoverTrigger } from "@components/Popover";
import { cn } from "@utils/helpers";
import dayjs, { Dayjs } from "dayjs";
import utc from "dayjs/plugin/utc";
import { CalendarIcon, ChevronLeftIcon, ChevronRightIcon } from "lucide-react";

dayjs.extend(utc);

export type DateRange = { from?: Date; to?: Date };

type Preset = { label: string; range: () => DateRange };

const PRESETS: Preset[] = [
  { label: "All Time", range: () => ({}) },
  {
    label: "Last Month",
    range: () => ({
      from: dayjs.utc().subtract(30, "day").startOf("day").toDate(),
      to: dayjs.utc().endOf("day").toDate(),
    }),
  },
  { label: "Last 14 Days", range: last14Days },
  {
    label: "Yesterday",
    range: () => ({
      from: dayjs.utc().subtract(1, "day").startOf("day").toDate(),
      to: dayjs.utc().subtract(1, "day").endOf("day").toDate(),
    }),
  },
  {
    label: "Today",
    range: () => ({ from: dayjs.utc().startOf("day").toDate(), to: dayjs.utc().endOf("day").toDate() }),
  },
];

export function last14Days(): DateRange {
  return { from: dayjs.utc().subtract(14, "day").startOf("day").toDate(), to: dayjs.utc().endOf("day").toDate() };
}

function presetLabel(value: DateRange): string | null {
  if (!value.from && !value.to) return "All Time";
  if (!value.from || !value.to) return null;
  for (const p of PRESETS) {
    if (p.label === "All Time") continue;
    const r = p.range();
    if (!r.from || !r.to) continue;

    if (Math.abs(r.from.getTime() - value.from.getTime()) < 60_000 && Math.abs(r.to.getTime() - value.to.getTime()) < 60_000) {
      return p.label;
    }
  }
  return null;
}

export function isDefaultDateRange(value: DateRange): boolean {
  const def = last14Days();
  if (!value.from || !value.to) return false;
  return (
    Math.abs(def.from!.getTime() - value.from.getTime()) < 60_000 &&
    Math.abs(def.to!.getTime() - value.to.getTime()) < 60_000
  );
}

function triggerLabel(value: DateRange): string {
  const preset = presetLabel(value);
  if (preset) return preset;
  if (value.from && value.to) {
    return `${dayjs.utc(value.from).format("MMM D")} - ${dayjs.utc(value.to).format("MMM D, YYYY")}`;
  }
  return "All Time";
}

export default function DateRangePicker({
  value,
  onChange,
}: {
  value: DateRange;
  onChange: (next: DateRange) => void;
}) {
  const [open, setOpen] = useState(false);
  const [viewMonth, setViewMonth] = useState(() => dayjs.utc(value.from ?? value.to ?? new Date()).startOf("month"));
  const [draft, setDraft] = useState<DateRange>(value);

  const openChange = (next: boolean) => {
    if (next) {
      setDraft(value);
      setViewMonth(dayjs.utc(value.from ?? value.to ?? new Date()).startOf("month"));
    }
    setOpen(next);
  };

  const pickDay = (day: Dayjs) => {
    if (!draft.from || (draft.from && draft.to)) {
      setDraft({ from: day.startOf("day").toDate(), to: undefined });
      return;
    }
    if (day.isBefore(draft.from)) {
      setDraft({ from: day.startOf("day").toDate(), to: undefined });
      return;
    }
    const next = { from: draft.from, to: day.endOf("day").toDate() };
    setDraft(next);
    onChange(next);
    setOpen(false);
  };

  return (
    <Popover open={open} onOpenChange={openChange}>
      <PopoverTrigger asChild>
        <Button variant="secondary" className="max-w-65 justify-start text-left font-normal">
          <CalendarIcon size={16} className="shrink-0" />
          {triggerLabel(value)}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-auto p-0" align="start" sideOffset={7}>
        <div className="flex items-center gap-1 p-2 border-b border-nb-gray-900 flex-wrap">
          {PRESETS.map((p) => (
            <button
              key={p.label}
              className={cn(
                "px-2.5 py-1.5 rounded-sm text-xs transition-colors cursor-pointer",
                presetLabel(draft) === p.label
                  ? "bg-nb-gray-800 text-white"
                  : "text-nb-gray-300 hover:bg-nb-gray-900 hover:text-white",
              )}
              onClick={() => {
                const r = p.range();
                setDraft(r);
                onChange(r);
                setOpen(false);
              }}
            >
              {p.label}
            </button>
          ))}
        </div>

        <div className="flex items-center justify-between px-3 pt-3">
          <button
            aria-label="Previous month"
            className="w-7 h-7 flex items-center justify-center text-nb-gray-400 hover:text-white hover:bg-nb-gray-900 rounded-sm transition-colors cursor-pointer"
            onClick={() => setViewMonth((m) => m.subtract(1, "month"))}
          >
            <ChevronLeftIcon size={16} />
          </button>
          <button
            aria-label="Next month"
            className="w-7 h-7 flex items-center justify-center text-nb-gray-400 hover:text-white hover:bg-nb-gray-900 rounded-sm transition-colors cursor-pointer"
            onClick={() => setViewMonth((m) => m.add(1, "month"))}
          >
            <ChevronRightIcon size={16} />
          </button>
        </div>

        <div className="flex gap-4 p-3 pt-1">
          <MonthGrid month={viewMonth} range={draft} onPick={pickDay} />
          <MonthGrid month={viewMonth.add(1, "month")} range={draft} onPick={pickDay} />
        </div>

        <div className="flex items-center gap-2 p-3 border-t border-nb-gray-900 text-xs text-nb-gray-300">
          <DateTimeBox value={draft.from} />
          <span className="text-nb-gray-500">–</span>
          <DateTimeBox value={draft.to} />
          <span className="text-nb-gray-500 shrink-0">UTC</span>
        </div>
      </PopoverContent>
    </Popover>
  );
}

function MonthGrid({
  month,
  range,
  onPick,
}: {
  month: Dayjs;
  range: DateRange;
  onPick: (day: Dayjs) => void;
}) {
  const start = month.startOf("month").startOf("week");
  const end = month.endOf("month").endOf("week");
  const days: Dayjs[] = [];
  for (let d = start; d.isBefore(end) || d.isSame(end, "day"); d = d.add(1, "day")) {
    days.push(d);
  }

  const from = range.from ? dayjs.utc(range.from) : null;
  const to = range.to ? dayjs.utc(range.to) : null;

  const today = dayjs.utc();

  return (
    <div className="w-56">
      <p className="text-sm font-medium text-nb-gray-100 text-center mb-2">{month.format("MMMM YYYY")}</p>
      <div className="grid grid-cols-7 gap-y-1">
        {["Su", "Mo", "Tu", "We", "Th", "Fr", "Sa"].map((d) => (
          <span key={d} className="text-[10px] uppercase text-nb-gray-500 text-center">
            {d}
          </span>
        ))}
        {days.map((day) => {
          if (day.month() !== month.month()) {
            return <div key={day.format("YYYY-MM-DD")} className="h-8" />;
          }
          const isFrom = !!from && day.isSame(from, "day");
          const isTo = !!to && day.isSame(to, "day");
          const isEndpoint = isFrom || isTo;
          const inRange = !!from && !!to && day.isAfter(from, "day") && day.isBefore(to, "day");
          const isToday = day.isSame(today, "day");

          return (
            <div
              key={day.format("YYYY-MM-DD")}
              className={cn(
                "h-8 flex items-center",
                (inRange || isEndpoint) && "bg-nb-gray-800",
                isFrom && "rounded-l-full",
                isTo && "rounded-r-full",
                isFrom && isTo && "rounded-full",
              )}
            >
              <button
                onClick={() => onPick(day)}
                className={cn(
                  "w-8 h-8 shrink-0 text-xs rounded-full transition-colors text-nb-gray-200 cursor-pointer",
                  !isEndpoint && "hover:bg-nb-gray-700",
                  isToday && !isEndpoint && "ring-1 ring-inset ring-netbird text-netbird-400",
                  isEndpoint && "bg-netbird text-white font-medium",
                )}
              >
                {day.date()}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function DateTimeBox({ value }: { value?: Date }) {
  return (
    <span className="flex-1 bg-nb-gray-900 border border-nb-gray-800 rounded-sm px-2 py-1.5 text-center tabular-nums">
      {value ? dayjs.utc(value).format("YYYY/MM/DD · HH:mm") : "—"}
    </span>
  );
}
