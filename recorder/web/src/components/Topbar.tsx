"use client";

import React from "react";
import Image from "next/image";
import { useAuth } from "@hooks/useAuth";
import { Popover, PopoverContent, PopoverTrigger } from "@components/Popover";
import { LogOutIcon } from "lucide-react";

export default function Topbar() {
  const auth = useAuth();
  const label = auth?.name || auth?.email || "Account";
  const initial = label.charAt(0).toUpperCase();

  return (
    <div className="h-16.25 flex items-center justify-between border-b border-zinc-700/40 bg-nb-gray px-4 md:px-6">
      <div className="flex items-center gap-3">
        <Image src="/netbird-full.svg" height={22} width={128} alt="NetBird" priority />
        <span className="text-nb-gray-500">/</span>
        <span className="text-nb-gray-300 text-sm font-medium">SSH Session Recordings</span>
      </div>

      {auth?.auth_enabled && (
        <Popover>
          <PopoverTrigger asChild>
            <button
              className="flex items-center justify-center w-8 h-8 rounded-full bg-green-600 text-white text-md font-medium hover:bg-green-700 transition-colors cursor-pointer"
              aria-label="Account menu"
            >
              {initial}
            </button>
          </PopoverTrigger>
          <PopoverContent className="w-60 p-1" align="end" sideOffset={10}>
            <div className="px-3 py-2.5">
              {auth.name && <p className="text-sm font-medium text-white truncate">{auth.name}</p>}
              {auth.email && <p className="text-xs text-nb-gray-400 truncate">{auth.email}</p>}
            </div>
            <div className="border-t border-nb-gray-800 my-1" />
            <a
              href="/auth/logout"
              className="flex items-center gap-2 px-3 py-2 rounded-md text-sm text-nb-gray-300 hover:bg-nb-gray-800 hover:text-white transition-colors"
            >
              <LogOutIcon size={14} />
              Log out
            </a>
          </PopoverContent>
        </Popover>
      )}
    </div>
  );
}
