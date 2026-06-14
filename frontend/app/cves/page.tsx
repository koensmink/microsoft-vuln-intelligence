import Link from "next/link";
import { getJson } from "../../src/api";

type Cve = {
  id: number;
  cve_id: string;
  title: string | null;
  severity: string | null;
  cvss_score: number | null;
  exploited: boolean;
  publicly_disclosed: boolean;
  affected_product_count: number | null;
  release: { release_name: string } | null;
};

export default async function CvesPage() {
  const cves = await getJson<Cve[]>("/cves", []);

  return (
    <section className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Vulnerabilities</h1>
        <p className="text-slate-400">MSRC CVRF vulnerabilities by Microsoft product context.</p>
      </div>
      <form className="grid gap-3 rounded border border-slate-800 p-4 md:grid-cols-5">
        <input className="rounded bg-slate-900 p-2" name="search" placeholder="Search CVE, title, product" />
        <select className="rounded bg-slate-900 p-2" name="severity"><option value="">Any severity</option><option>Critical</option><option>Important</option><option>Moderate</option><option>Low</option></select>
        <select className="rounded bg-slate-900 p-2" name="exploited"><option value="">Exploited?</option><option value="true">Yes</option><option value="false">No</option></select>
        <select className="rounded bg-slate-900 p-2" name="publicly_disclosed"><option value="">Publicly disclosed?</option><option value="true">Yes</option><option value="false">No</option></select>
        <input className="rounded bg-slate-900 p-2" name="release_name" placeholder="Release" />
      </form>
      <div className="overflow-x-auto rounded border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-slate-300"><tr><th className="p-3">CVE</th><th className="p-3">Title</th><th className="p-3">Release</th><th className="p-3">Products</th><th className="p-3">Severity</th><th className="p-3">CVSS</th><th className="p-3">Exploited</th><th className="p-3">Public</th></tr></thead>
          <tbody>{cves.map((cve) => <tr key={cve.cve_id} className="border-t border-slate-800"><td className="p-3"><Link className="text-blue-400 hover:underline" href={`/cves/${cve.cve_id}`}>{cve.cve_id}</Link></td><td className="p-3">{cve.title ?? "Untitled"}</td><td className="p-3">{cve.release?.release_name ?? "-"}</td><td className="p-3">{cve.affected_product_count ?? "-"}</td><td className="p-3">{cve.severity ?? "Unknown"}</td><td className="p-3">{cve.cvss_score ?? "-"}</td><td className="p-3">{cve.exploited ? "Yes" : "No"}</td><td className="p-3">{cve.publicly_disclosed ? "Yes" : "No"}</td></tr>)}</tbody>
        </table>
      </div>
    </section>
  );
}
