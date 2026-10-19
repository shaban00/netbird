import useSWR from "swr";
import { apiFetcher } from "@utils/fetcher";
import { SessionListResponse } from "@utils/types";

export interface SessionsFilter {
  q?: string;
  statuses?: string[];
  after?: string;
  before?: string;
  limit?: number;
  offset?: number;
}

export function useSessions(filter: SessionsFilter) {
  const params = new URLSearchParams();
  if (filter.q) params.set("q", filter.q);
  for (const status of filter.statuses ?? []) params.append("status", status);
  if (filter.after) params.set("after", filter.after);
  if (filter.before) params.set("before", filter.before);
  if (filter.limit) params.set("limit", String(filter.limit));
  if (filter.offset) params.set("offset", String(filter.offset));

  const { data, error, isLoading, mutate } = useSWR(
    `/api/sessions?${params.toString()}`,
    apiFetcher<SessionListResponse>,
    { revalidateOnFocus: false },
  );

  return {
    sessions: data?.sessions ?? [],
    total: data?.total ?? 0,
    limit: data?.limit ?? filter.limit ?? 0,
    offset: data?.offset ?? filter.offset ?? 0,
    isLoading,
    error,
    refresh: mutate,
  };
}
