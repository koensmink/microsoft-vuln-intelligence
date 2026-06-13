export const apiBase = process.env.NEXT_PUBLIC_API_BASE_URL ?? 'http://localhost:8000/api/v1';
export async function getJson<T>(path: string, fallback: T): Promise<T> {
  try { const res = await fetch(`${apiBase}${path}`, { next: { revalidate: 60 } }); return res.ok ? await res.json() : fallback; } catch { return fallback; }
}
