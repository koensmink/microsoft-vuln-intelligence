import Link from "next/link";
import "./globals.css";

export const metadata = { title: "Microsoft Vulnerability Intelligence" };

const navItems = [
  { href: "/", label: "Overview", icon: "◇" },
  { href: "/cves", label: "CVE Explorer", icon: "⌕" },
  { href: "/releases", label: "Releases", icon: "▣" },
  { href: "/cves?kev=true", label: "KEV Catalog", icon: "✦" },
  { href: "/cves?min_epss=0.10", label: "EPSS Insights", icon: "⌁" },
  { href: "/", label: "Reports", icon: "▤" },
  { href: "/", label: "Settings", icon: "⚙" },
];

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body>
        <div className="min-h-screen bg-[#020817] text-slate-100">
          <aside className="fixed inset-y-0 left-0 z-30 hidden w-72 border-r border-cyan-400/10 bg-slate-950/95 px-5 py-6 shadow-2xl shadow-cyan-950/20 backdrop-blur xl:block">
            <Link className="flex items-center gap-3" href="/">
              <span className="grid h-11 w-11 place-items-center rounded-2xl border border-cyan-300/30 bg-cyan-400/10 text-cyan-200">MS</span>
              <span>
                <span className="block text-sm font-black uppercase tracking-[0.22em] text-cyan-100">Vuln Intel</span>
                <span className="text-xs text-slate-500">Security Operations</span>
              </span>
            </Link>
            <nav className="mt-10 space-y-2">
              {navItems.map((item) => (
                <Link key={`${item.label}-${item.href}`} className="group flex items-center gap-3 rounded-2xl px-3 py-3 text-sm font-semibold text-slate-400 transition hover:bg-cyan-400/10 hover:text-cyan-100" href={item.href}>
                  <span className="grid h-8 w-8 place-items-center rounded-xl bg-slate-900 text-cyan-300 group-hover:bg-cyan-400/15">{item.icon}</span>
                  {item.label}
                </Link>
              ))}
            </nav>
            <div className="absolute bottom-6 left-5 right-5 rounded-2xl border border-slate-800 bg-slate-900/70 p-4 text-xs text-slate-400">
              <p className="font-semibold uppercase tracking-[0.2em] text-slate-500">Secure feed</p>
              <p className="mt-2">MSRC, NVD, FIRST EPSS, and CISA KEV signals.</p>
            </div>
          </aside>
          <main className="min-w-0 px-4 py-4 sm:px-6 lg:px-8 xl:ml-72">{children}</main>
        </div>
      </body>
    </html>
  );
}
