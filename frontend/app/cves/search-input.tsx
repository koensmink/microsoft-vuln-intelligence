"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef, useState, useTransition } from "react";

export function SearchInput({ initialValue }: { initialValue?: string }) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const [value, setValue] = useState(initialValue ?? "");
  const [, startTransition] = useTransition();
  const generation = useRef(0);

  useEffect(() => {
    const requestGeneration = ++generation.current;
    const timer = window.setTimeout(() => {
      if (requestGeneration !== generation.current) return;
      const normalizedValue = value.trim();
      if ((searchParams.get("search") ?? "") === normalizedValue) return;
      const next = new URLSearchParams(searchParams.toString());
      if (normalizedValue) next.set("search", normalizedValue);
      else next.delete("search");
      next.delete("offset");
      startTransition(() => router.replace(`${pathname}?${next.toString()}`, { scroll: false }));
    }, 300);

    return () => {
      generation.current += 1;
      window.clearTimeout(timer);
    };
  }, [pathname, router, searchParams, value]);

  return <input aria-label="Search CVEs" className="rounded-xl border border-slate-800 bg-slate-950 p-3" name="search" placeholder="Search CVE, title, product" value={value} onChange={(event) => setValue(event.target.value)} />;
}
