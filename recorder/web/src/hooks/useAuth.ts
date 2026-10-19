import useSWR from "swr";
import { apiFetcher } from "@utils/fetcher";

export interface AuthInfo {
  auth_enabled: boolean;
  name?: string;
  email?: string;
  subject?: string;
}

export function useAuth() {
  const { data } = useSWR<AuthInfo>("/api/me", apiFetcher<AuthInfo>, {
    revalidateOnFocus: false,
    shouldRetryOnError: false,
  });
  return data;
}
