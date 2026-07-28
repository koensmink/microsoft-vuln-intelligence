import { cache } from "react";

export const apiBase =
  process.env.API_BASE_URL ??
  process.env.NEXT_PUBLIC_API_BASE_URL ??
  "http://backend:8000/api/v1";

export async function getJson<T>(path: string, fallback: T): Promise<T> {
  const url = `${apiBase}${path}`;

  try {
    const res = await fetch(url, {
      next: { revalidate: 300 },
    });

    if (!res.ok) {
      console.error(`API request failed: ${res.status} ${url}`);
      return fallback;
    }

    return (await res.json()) as T;
  } catch (error) {
    console.error(`API request failed: ${url}`, error);
    return fallback;
  }
}

export const getGlobalStats = cache(async <T,>(): Promise<T> =>
  getJson<T>("/stats", {} as T),
);
