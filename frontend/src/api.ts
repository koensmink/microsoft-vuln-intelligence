export const apiBase =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://backend:8000/api/v1";

export async function getJson<T>(path: string, fallback: T): Promise<T> {
  const url = `${apiBase}${path}`;

  try {
    const res = await fetch(url, {
      cache: "no-store",
    });

    if (!res.ok) {
      return fallback;
    }

    return (await res.json()) as T;
  } catch {
    return fallback;
  }
}
