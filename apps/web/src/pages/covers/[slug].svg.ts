import type { APIRoute } from "astro";
import { renderCoverSvg, getTopic, factsFixed } from "@ichiji/core";
import { parseJson } from "@ichiji/db";
import { cacheMediaPage, catalog } from "../../server/media";

/** カバー画像（5-3 の5）。CVE番号・トピック・緊急度入りのテンプレートから自動生成する */
export const GET: APIRoute = async (context) => {
  const slug = context.params.slug ?? "";
  const repo = catalog();
  const article = await repo.getArticleBySlug(slug);
  if (!article) return new Response("not found", { status: 404 });
  cacheMediaPage(context, 3600);
  const facts = await repo.getFacts(parseJson<string[]>(article.cve_ids, [])[0] ?? article.primary_cve);
  const pkg = facts?.packages[0];
  const fixed = facts ? factsFixed(facts.packages) : [];
  const parts = article.title.split("｜");
  const svg = renderCoverSvg({
    cveId: article.primary_cve,
    packageLabel: pkg?.name ?? "",
    headline: parts[1] ?? parts[0] ?? article.title,
    topicLabel: getTopic(article.topic)?.name.replace(/（.*）/, "") ?? article.topic,
    rank: facts?.rank ?? article.general_rank,
    fixed: fixed.length ? fixed[fixed.length - 1]! : null,
  });
  return new Response(svg, { headers: { "content-type": "image/svg+xml; charset=utf-8" } });
};
