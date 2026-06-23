type PowerShellCheck = {
  title?: string | null;
  command?: string | null;
  explanation?: string | null;
  applies_to?: string | null;
};

type AiContext = {
  plain_summary?: string | null;
  business_impact?: string | null;
  who_should_act?: string[] | null;
  what_to_check?: string[] | null;
  recommended_action?: string | null;
  technical_context?: string | null;
  limitations?: string[] | null;
  how_to_check?: string[] | null;
  powershell_checks?: PowerShellCheck[] | null;
  verification_notes?: string[] | null;
  confidence?: string | number | null;
};

function FieldText({ value }: { value?: string | null }) {
  return <p className="mt-2 text-sm leading-6 text-slate-300">{value?.trim() ? value : "—"}</p>;
}

function List({ items }: { items?: string[] | null }) {
  const visibleItems = items?.filter((item) => item.trim()) ?? [];
  if (visibleItems.length === 0) return <p className="empty-state mt-2">—</p>;
  return <ul className="mt-2 list-disc space-y-1 pl-5 text-sm leading-6 text-slate-300">{visibleItems.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ul>;
}

function PowerShellChecks({ items }: { items?: PowerShellCheck[] | null }) {
  const visibleItems = items?.filter((item) => item.title?.trim() || item.command?.trim() || item.explanation?.trim() || item.applies_to?.trim()) ?? [];
  if (visibleItems.length === 0) return <p className="empty-state mt-2">—</p>;
  return <div className="mt-2 space-y-3">{visibleItems.map((item, index) => <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3" key={`${item.title ?? "check"}-${index}`}>
    <p className="text-sm font-semibold text-slate-100">{item.title?.trim() ? item.title : "PowerShell controle"}</p>
    {item.command?.trim() ? <pre className="mt-2 overflow-x-auto rounded-lg bg-slate-950 p-3 text-xs text-cyan-100"><code>{item.command}</code></pre> : null}
    {item.explanation?.trim() ? <p className="mt-2 text-sm leading-6 text-slate-300">{item.explanation}</p> : null}
    {item.applies_to?.trim() ? <p className="mt-2 text-xs text-slate-500">Van toepassing op: {item.applies_to}</p> : null}
  </div>)}</div>;
}

function ConfidenceBadge({ confidence }: { confidence?: string | number | null }) {
  if (confidence == null || confidence === "") return null;
  return <span className="inline-flex rounded-full border border-cyan-300/30 bg-cyan-300/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-cyan-100">Confidence: {confidence}</span>;
}

export default function AiContextPanel({ initialContext }: { cveId: string; initialContext: AiContext | null }) {
  return <section className="card border-cyan-400/20 bg-slate-900/80">
    <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
      <div><p className="text-xs font-semibold uppercase tracking-[0.25em] text-cyan-300">AI context</p><h2 className="mt-1 text-xl font-semibold">Begrijpelijke uitleg</h2></div>
      <ConfidenceBadge confidence={initialContext?.confidence} />
    </div>
    {!initialContext ? <p className="empty-state mt-4">Nog geen begrijpelijke uitleg beschikbaar.</p> : <div className="mt-5 grid gap-4 lg:grid-cols-2">
      <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-4"><h3 className="font-semibold text-cyan-200">In gewone taal</h3><FieldText value={initialContext.plain_summary} /></div>
      <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-4"><h3 className="font-semibold text-cyan-200">Waarom relevant?</h3><FieldText value={initialContext.business_impact} /></div>
      <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-4"><h3 className="font-semibold text-cyan-200">Wie moet actie nemen?</h3><List items={initialContext.who_should_act} /></div>
      <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-4"><h3 className="font-semibold text-cyan-200">Wat controleren?</h3><List items={initialContext.what_to_check} /></div>
      <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-4"><h3 className="font-semibold text-cyan-200">Advies</h3><FieldText value={initialContext.recommended_action} /></div>
      <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-4"><h3 className="font-semibold text-cyan-200">Technische context</h3><FieldText value={initialContext.technical_context} /></div>
      <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-4 lg:col-span-2"><h3 className="font-semibold text-cyan-200">Praktisch verifiëren</h3><List items={initialContext.how_to_check} /></div>
      <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-4 lg:col-span-2"><h3 className="font-semibold text-cyan-200">Defensieve PowerShell-controles</h3><PowerShellChecks items={initialContext.powershell_checks} /></div>
      <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-4"><h3 className="font-semibold text-cyan-200">Verificatienotities</h3><List items={initialContext.verification_notes} /></div>
      <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-4"><h3 className="font-semibold text-cyan-200">Beperkingen</h3><List items={initialContext.limitations} /></div>
    </div>}
  </section>;
}
