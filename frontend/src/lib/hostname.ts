/** Mirrors the contract's `_parent_chain` / PUBLIC_SUFFIXES so the UI can say
 *  *why* a subdomain is covered by a listed parent. */
export const PUBLIC_SUFFIXES: readonly string[] = [
  "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "co.kr", "co.in",
  "co.nz", "co.za", "com.br", "com.cn", "com.mx", "com.tr", "com.sg", "com.ar", "com.hk",
  "github.io", "gitlab.io", "vercel.app", "netlify.app", "pages.dev", "workers.dev", "web.app",
  "firebaseapp.com", "herokuapp.com", "blogspot.com", "azurewebsites.net", "appspot.com",
];

/** Registrable-parent candidates, nearest first; >= 2 labels, stops at a public suffix. */
export function parentChain(host: string): string[] {
  const labels = host.split(".");
  const out: string[] = [];
  for (let i = 1; i < labels.length - 1; i++) {
    const parent = labels.slice(i).join(".");
    if (PUBLIC_SUFFIXES.includes(parent)) break;
    out.push(parent);
  }
  return out;
}
