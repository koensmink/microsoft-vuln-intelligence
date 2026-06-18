"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";

export type NavItem = { href: string; label: string; icon: string };

type SidebarNavProps = {
  items: NavItem[];
  variant?: "sidebar" | "mobile";
};

export function SidebarNav({ items, variant = "sidebar" }: SidebarNavProps) {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const currentQuery = searchParams.toString();
  const isMobile = variant === "mobile";

  return (
    <nav className={isMobile ? "mt-4 flex gap-2 overflow-x-auto pb-1" : "mt-10 space-y-2"}>
      {items.map((item) => {
        const [path, query] = item.href.split("?");
        const active = pathname === path && (!query || currentQuery === query);
        return (
          <Link
            key={`${item.label}-${item.href}`}
            className={`group flex items-center gap-3 rounded-2xl px-3 py-3 text-sm font-semibold transition ${isMobile ? "shrink-0" : ""} ${active ? "bg-cyan-400/15 text-cyan-50 ring-1 ring-cyan-300/30" : "text-slate-400 hover:bg-cyan-400/10 hover:text-cyan-100"}`}
            href={item.href}
          >
            <span className={`grid h-8 w-8 place-items-center rounded-xl ${active ? "bg-cyan-400/20 text-cyan-100" : "bg-slate-900 text-cyan-300 group-hover:bg-cyan-400/15"}`}>{item.icon}</span>
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}
