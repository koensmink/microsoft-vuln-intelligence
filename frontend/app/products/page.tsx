import { getJson } from '../../src/api';
export default async function Products(){const products=await getJson<any[]>('/products',[]);return <section><h1 className="mb-4 text-3xl font-bold">Products</h1><div className="card"><ul>{products.map(p=><li key={p.id} className="border-b border-slate-800 py-2">{p.name}<span className="text-slate-500"> {p.family}</span></li>)}</ul></div></section>}
