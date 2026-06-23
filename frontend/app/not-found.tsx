import Link from "next/link";

const notFoundGif = "https://media1.giphy.com/media/v1.Y2lkPTc5MGI3NjExM3p1MmlzcGFmN2ZqbmZveWJlcnhxendpbGw4NDRsamZoZ28zZjAxOCZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/utmZFnsMhUHqU/giphy.gif";

export default function NotFound() {
  return (
    <section className="flex min-h-[calc(100vh-2rem)] items-center justify-center py-10">
      <div className="mx-auto w-full max-w-3xl rounded-3xl border border-cyan-400/10 bg-slate-900/45 p-6 text-center shadow-2xl shadow-cyan-950/20 backdrop-blur sm:p-10">
        <p className="text-xs font-black uppercase tracking-[0.35em] text-cyan-300">HTTP 404</p>
        <h1 className="mt-4 text-4xl font-black tracking-tight text-slate-50 sm:text-5xl">HTTP 404</h1>
        <div className="mt-8 flex justify-center">
          <img
            alt="Animated 404 page not found illustration"
            className="max-h-80 w-full max-w-lg rounded-2xl border border-slate-800/80 object-contain shadow-xl shadow-black/30"
            src={notFoundGif}
          />
        </div>
        <p className="mx-auto mt-8 max-w-xl text-base text-slate-300 sm:text-lg">The page you are looking for does not exist.</p>
        <div className="mt-8 flex flex-col justify-center gap-3 sm:flex-row">
          <Link className="rounded-xl border border-cyan-400/25 bg-cyan-400/10 px-5 py-3 text-sm font-bold text-cyan-100 transition hover:bg-cyan-400/20" href="/">
            Back to Dashboard
          </Link>
          <Link className="rounded-xl border border-slate-800 bg-slate-950/70 px-5 py-3 text-sm font-bold text-slate-300 transition hover:border-cyan-400/40 hover:text-cyan-100" href="/cves">
            Search CVEs
          </Link>
        </div>
      </div>
    </section>
  );
}
