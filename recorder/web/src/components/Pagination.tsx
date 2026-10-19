"use client";

import React from "react";
import Button from "@components/Button";
import { ChevronLeftIcon, ChevronRightIcon, ChevronsLeftIcon, ChevronsRightIcon } from "lucide-react";

export interface PaginationProps {
  total: number;
  limit: number;
  offset: number;
  onOffsetChange: (offset: number) => void;
}

export default function Pagination({ total, limit, offset, onOffsetChange }: PaginationProps) {
  if (limit <= 0 || total <= limit) return null;

  const page = Math.floor(offset / limit) + 1;
  const pageCount = Math.max(1, Math.ceil(total / limit));
  const rangeStart = offset + 1;
  const rangeEnd = Math.min(offset + limit, total);

  const goToPage = (p: number) => onOffsetChange((p - 1) * limit);

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 mt-5 text-sm text-nb-gray-400">
      <p>
        Showing <span className="text-gray-100 font-medium">{rangeStart}</span> to{" "}
        <span className="text-gray-100 font-medium">{rangeEnd}</span> of{" "}
        <span className="text-gray-100 font-medium">{total}</span>
      </p>

      <div className="flex items-center gap-1 border border-gray-700/40 rounded-md p-1 bg-nb-gray-920">
        <Button
          variant="secondary"
          size="icon"
          border={1}
          onClick={() => goToPage(1)}
          disabled={page <= 1}
          aria-label="First page"
        >
          <ChevronsLeftIcon size={15} />
        </Button>
        <Button
          variant="secondary"
          size="icon"
          border={1}
          onClick={() => goToPage(page - 1)}
          disabled={page <= 1}
          aria-label="Previous page"
        >
          <ChevronLeftIcon size={15} />
        </Button>
        <span className="px-2 text-xs text-nb-gray-300 tabular-nums whitespace-nowrap">
          {page} of {pageCount}
        </span>
        <Button
          variant="secondary"
          size="icon"
          border={1}
          onClick={() => goToPage(page + 1)}
          disabled={page >= pageCount}
          aria-label="Next page"
        >
          <ChevronRightIcon size={15} />
        </Button>
        <Button
          variant="secondary"
          size="icon"
          border={1}
          onClick={() => goToPage(pageCount)}
          disabled={page >= pageCount}
          aria-label="Last page"
        >
          <ChevronsRightIcon size={15} />
        </Button>
      </div>
    </div>
  );
}
