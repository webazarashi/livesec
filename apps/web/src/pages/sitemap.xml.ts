import type { APIRoute } from "astro";
import { TOPICS } from "@ichiji/core";
import { catalog, cacheMediaPage } from "../server/media";

export const GET: APIRoute = async (context) => {
  cacheMediaPage(context, 3600);
  const origin = context.url.origin;
  const articles = await catalog().listAllArticleSlugs();
  const urls = [
    "/",
    "/articles/",
    "/urgent/",
    "/topics/",
    "/tags/",
    "/cve/",
    "/about/",
    "/editorial-policy/",
    ...TOPICS.map((t) => `/${t.key}/`),
  ].map((p) => `<url><loc>${origin}${p}</loc></url>`);
  const articleUrls = articles.map((a) => `<url><loc>${origin}/${a.topic}/${a.slug}/</loc><lastmod>${a.updated_at.slice(0, 10)}</lastmod></url>`);
  const xml = `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${[...urls, ...articleUrls].join("")}</urlset>`;
  return new Response(xml, { headers: { "content-type": "application/xml; charset=utf-8" } });
};
