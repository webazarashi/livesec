import type { APIRoute } from "astro";

export const GET: APIRoute = ({ url }) =>
  new Response(`User-agent: *\nDisallow: /app/\nDisallow: /admin/\nDisallow: /api/\nSitemap: ${url.origin}/sitemap.xml\n`, {
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
