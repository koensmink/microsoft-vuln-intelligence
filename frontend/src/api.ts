export const apiBase =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://backend:8000/api/v1";

export async function getJson<T>(path: string, fallback: T): Promise<T> {
  const url = `${apiBase}${path}`;

  const res = await fetch(url, {
    cache: "no-store",
  });

  if (!res.ok) {
    throw new Error(`API request failed: ${url} -> ${res.status}`);
  }

  return (await res.json()) as T;
}
