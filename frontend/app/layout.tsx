import Link from "next/link";
import "./globals.css";

export const metadata = { title: "Microsoft Vulnerability Intelligence" };

const navItems = [
  { href: "/", label: "Dashboard" },
  { href: "/cves", label: "Vulnerabilities" },
  { href: "/releases", label: "Releases" },
  { href: "/products", label: "Products" },
];

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return <html lang="en" className="dark"><body><div className="min-h-screen bg-slate-950 text-slate-100"><header className="sticky top-0 z-20 border-b border-slate-800/80 bg-slate-950/85 backdrop-blur"><div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-4 sm:px-6 lg:px-8"><Link className="text-sm font-black uppercase tracking-[0.25em] text-cyan-200" href="/">MS Vuln Intel</Link><nav className="hidden items-center gap-5 text-sm text-slate-300 md:flex">{navItems.map((item) => <Link key={item.href} className="hover:text-white" href={item.href}>{item.label}</Link>)}</nav></div></header><div className="mx-auto grid max-w-7xl gap-0 lg:grid-cols-[16rem_1fr]"><aside className="hidden border-r border-slate-800/80 px-5 py-8 lg:block"><p className="text-xs font-semibold uppercase tracking-[0.3em] text-slate-500">Navigation</p><nav className="mt-5 space-y-2">{navItems.map((item) => <Link key={item.href} className="block rounded-xl px-3 py-2 text-sm text-slate-300 hover:bg-slate-900 hover:text-white" href={item.href}>{item.label}</Link>)}</nav></aside><main className="min-w-0 px-4 py-6 sm:px-6 lg:px-8">{children}</main></div></div></body></html>;
}
