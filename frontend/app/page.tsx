import Link from "next/link";
import { getJson } from "../../src/api";

type Cve = {
  id: number;
  cve_id: string;
  title: string;
  severity: string | null;
  impact: string | null;
  exploited: boolean;
  publicly_disclosed: boolean;
};

export default async function CvesPage() {
  const cves = await getJson<Cve[]>("/cves", []);

  return (
    <section>
      <h1 className="mb-6 text-2xl font-semibold">Vulnerabilities</h1>

      <div className="overflow-x-auto rounded border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-slate-300">
            <tr>
              <th className="p-3">CVE</th>
              <th className="p-3">Title</th>
              <th className="p-3">Severity</th>
              <th className="p-3">Impact</th>
              <th className="p-3">Exploited</th>
              <th className="p-3">Public</th>
            </tr>
          </thead>
          <tbody>
            {cves.map((cve) => (
              <tr key={cve.cve_id} className="border-t border-slate-800">
                <td className="p-3">
                  <Link
                    className="text-blue-400 hover:underline"
                    href={`/cves/${cve.cve_id}`}
                  >
                    {cve.cve_id}
                  </Link>
                </td>
                <td className="p-3">{cve.title}</td>
                <td className="p-3">{cve.severity ?? "Unknown"}</td>
                <td className="p-3">{cve.impact ?? "Unknown"}</td>
                <td className="p-3">{cve.exploited ? "Yes" : "No"}</td>
                <td className="p-3">
                  {cve.publicly_disclosed ? "Yes" : "No"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
