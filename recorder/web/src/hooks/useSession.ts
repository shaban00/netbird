import useSWR from "swr";
import { apiFetcher } from "@utils/fetcher";
import { Session } from "@utils/types";

export function useSession(id: string | undefined) {
  const { data, error, isLoading, mutate } = useSWR(
    id ? `/api/sessions/${encodeURIComponent(id)}` : null,
    apiFetcher<Session>,
  );

  return { session: data, isLoading, error, refresh: mutate };
}
