import type { APIRoute } from "astro";
import { SITE } from "@ichiji/core";
import { catalog, cacheMediaPage } from "../server/media";

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

export const GET: APIRoute = async (context) => {
  cacheMediaPage(context, 600);
  const articles = await catalog().listArticles({ limit: 50 });
  const origin = context.url.origin;
  const items = articles
    .map(
      (a) => `<item><title>${esc(a.title)}</title><link>${origin}/${a.topic}/${a.slug}/</link><guid isPermaLink="true">${origin}/${a.topic}/${a.slug}/</guid><pubDate>${new Date(a.published_at).toUTCString()}</pubDate><category>${esc(a.topic)}</category><description>${esc(a.why_read)}</description></item>`,
    )
    .join("");
  const xml = `<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>${esc(SITE.name)}</title><link>${origin}/</link><description>${esc(SITE.description)}</description><language>ja</language>${items}</channel></rss>`;
  return new Response(xml, { headers: { "content-type": "application/rss+xml; charset=utf-8" } });
};
