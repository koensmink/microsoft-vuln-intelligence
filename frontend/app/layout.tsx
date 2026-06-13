import './globals.css';
export const metadata = { title: 'Microsoft Vulnerability Intelligence' };
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return <html lang="en" className="dark"><body><nav className="border-b border-slate-800 p-4"><a className="font-semibold" href="/">MS Vulnerability Intelligence</a><span className="ml-6 space-x-4 text-sm text-slate-300"><a href="/cves">Vulnerabilities</a><a href="/releases">Releases</a><a href="/products">Products</a></span></nav><main className="mx-auto max-w-6xl p-6">{children}</main></body></html>;
}
