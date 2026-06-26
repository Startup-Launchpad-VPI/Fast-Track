/**
 * Cloudflare Pages middleware — shared-password gate for selected folders.
 *
 * A request is protected when its path falls under a folder listed in
 * /private.json (e.g. "Board-Notes" protects /Board-Notes and /Board-Notes/*).
 * Protected requests require HTTP Basic Auth; the password is read from the
 * SITE_PASSWORD environment variable (set it in the Cloudflare dashboard as an
 * encrypted variable — never commit it). Any username is accepted; only the
 * password is checked.
 *
 * Public paths pass straight through, so there is no overhead for the rest of
 * the site.
 */
import PRIVATE from "../private.json";

const REALM = "Fast Track — internal";

function unauthorized() {
  return new Response("Authentication required.", {
    status: 401,
    headers: {
      "WWW-Authenticate": `Basic realm="${REALM}", charset="UTF-8"`,
      "content-type": "text/plain; charset=utf-8",
    },
  });
}

function isProtected(pathname) {
  let path;
  try {
    path = decodeURIComponent(pathname);
  } catch {
    path = pathname;
  }
  return PRIVATE.some((dir) => {
    const base = "/" + String(dir).replace(/^\/+|\/+$/g, "");
    return path === base || path.startsWith(base + "/");
  });
}

export const onRequest = async (context) => {
  const { request, env, next } = context;
  const url = new URL(request.url);

  if (!isProtected(url.pathname)) return next();

  // No password configured -> fail closed (deny) rather than expose the page.
  const password = env.SITE_PASSWORD;
  if (!password) return unauthorized();

  const header = request.headers.get("Authorization") || "";
  if (header.startsWith("Basic ")) {
    let decoded = "";
    try {
      decoded = atob(header.slice(6));
    } catch {}
    const idx = decoded.indexOf(":");
    const provided = idx === -1 ? decoded : decoded.slice(idx + 1);
    if (provided === password) return next();
  }
  return unauthorized();
};
