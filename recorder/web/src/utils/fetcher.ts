export async function apiFetcher<T>(url: string): Promise<T> {
  const res = await fetch(url);

  if (res.status === 401) {
    const returnTo = window.location.pathname + window.location.search;
    window.location.href = `/auth/login?return_to=${encodeURIComponent(returnTo)}`;
    
    throw new Error("unauthenticated");
  }

  if (!res.ok) {
    throw new Error(`request failed: ${res.status}`);
  }

  return res.json() as Promise<T>;
}
