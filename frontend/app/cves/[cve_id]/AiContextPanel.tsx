"use client";

import { useState } from "react";
import { apiBase } from "../../../src/api";

function browserApiBase() {
  if (typeof window === "undefined") return apiBase;
  try {
    const url = new URL(apiBase);
    if (url.hostname === "backend") {
      url.hostname = window.location.hostname;
      url.port = "8000";
    }
    return url.toString().replace(/\/$/, "");
  } catch {
    return apiBase;
  }
}

type AiContext = {
  plain_summary: string;
  business_impact: string;
  who_should_act: string[];
  what_to_check: string[];
  recommended_action: string;
  limitations: string[];
};

function List({ items }: { items?: string[] }) {
  if (!items?.length) return <p className="empty-state mt-2">—</p>;
  return <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-slate-300">{items.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ul>;
}

export default function AiContextPanel({ cveId, initialContext }: { cveId: string; initialContext: AiContext | null }) {
  const [context, setContext] = useState<AiContext | null>(initialContext);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function generate() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${browserApiBase()}/cves/${encodeURIComponent(cveId)}/ai-context/generate`, { method: "POST" });
      const data = await res.json().catch(() => null);
      if (!res.ok) throw new Error(data?.detail ?? "Uitleg genereren is mislukt.");
      setContext(data as AiContext);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Uitleg genereren is mislukt.");
    } finally {
      setLoading(false);
    }
  }

  return <section className="card border-cyan-400/20 bg-slate-900/80">
    <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
      <div><p className="text-xs font-semibold uppercase tracking-[0.25em] text-cyan-300">AI context</p><h2 className="mt-1 text-xl font-semibold">Begrijpelijke uitleg</h2></div>
      <button onClick={generate} disabled={loading} className="rounded-xl border border-cyan-400/30 bg-cyan-400/10 px-4 py-2 text-sm font-semibold text-cyan-100 hover:bg-cyan-400/20 disabled:cursor-not-allowed disabled:opacity-60">{loading ? "Genereren…" : "Genereer uitleg"}</button>
    </div>
    {error ? <p className="mt-4 rounded-xl border border-rose-400/30 bg-rose-950/40 p-3 text-sm text-rose-200">{error}</p> : null}
    {!context ? <p className="empty-state mt-4">Nog geen begrijpelijke uitleg beschikbaar. Genereer uitleg om server-side AI-context op te slaan.</p> : <div className="mt-5 grid gap-4 lg:grid-cols-2">
      <div className="rounded-2xl bg-slate-950/60 p-4"><h3 className="font-semibold text-cyan-200">In gewone taal</h3><p className="mt-2 text-sm text-slate-300">{context.plain_summary}</p></div>
      <div className="rounded-2xl bg-slate-950/60 p-4"><h3 className="font-semibold text-cyan-200">Waarom is dit relevant?</h3><p className="mt-2 text-sm text-slate-300">{context.business_impact}</p></div>
      <div className="rounded-2xl bg-slate-950/60 p-4"><h3 className="font-semibold text-cyan-200">Wie moet actie nemen?</h3><List items={context.who_should_act} /></div>
      <div className="rounded-2xl bg-slate-950/60 p-4"><h3 className="font-semibold text-cyan-200">Wat moet ik controleren?</h3><List items={context.what_to_check} /></div>
      <div className="rounded-2xl bg-slate-950/60 p-4"><h3 className="font-semibold text-cyan-200">Advies</h3><p className="mt-2 text-sm text-slate-300">{context.recommended_action}</p></div>
      <div className="rounded-2xl bg-slate-950/60 p-4"><h3 className="font-semibold text-cyan-200">Beperkingen</h3><List items={context.limitations} /></div>
    </div>}
  </section>;
}
