"use client";

import React, { Suspense } from "react";
import SessionDetail from "@components/SessionDetail";
import SessionsList from "@components/SessionsList";
import { useRouter, useSearchParams } from "next/navigation";

export default function Page() {
  return (
    <Suspense>
      <PageContent />
    </Suspense>
  );
}

function PageContent() {
  const router = useRouter();
  const params = useSearchParams();
  const id = params.get("id");

  if (id) {
    return <SessionDetail id={id} onBack={() => router.replace("/")} />;
  }

  return <SessionsList onSelect={(sessionId) => router.replace(`/?id=${encodeURIComponent(sessionId)}`)} />;
}
