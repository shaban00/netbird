"use client";

import React, { useEffect, useRef } from "react";
import "asciinema-player/dist/bundle/asciinema-player.css";
import { create, Player } from "asciinema-player";


export default function CastPlayer({
  src,
  live = false,
  onEnded,
}: {
  src: string;
  live?: boolean;
  onEnded?: () => void;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const playerRef = useRef<Player | null>(null);

  useEffect(() => {
    if (!containerRef.current || !src) return;
    const player = create(src, containerRef.current, {
      terminalFontSize: "small",
      fit: "width",
      autoPlay: live,
      theme: "tango",
    });
    playerRef.current = player;
    if (onEnded) {
      player.addEventListener("ended", onEnded);
    }
    return () => {
      player.dispose();
      playerRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [src, live]);

  return (
    <div className="relative">
      {live && (
        <span className="absolute top-2 right-2 z-10 inline-flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-white bg-red-600 rounded-sm px-2 py-1">
          <span className="w-1.5 h-1.5 rounded-full bg-white animate-pulse" />
          Live
        </span>
      )}
      <div
        ref={containerRef}
        className="rounded-md border border-nb-gray-900 overflow-hidden bg-nb-gray-920"
      />
    </div>
  );
}
