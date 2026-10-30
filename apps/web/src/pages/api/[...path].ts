import type { APIRoute } from "astro";
import { handleApi } from "../../server/api";
import { getEnv } from "../../server/env";

/** /api/* は Hono に渡す（11章：API は Hono） */
export const ALL: APIRoute = (context) =>
  handleApi(context.request, getEnv(), context.cache, context.locals.cfContext as ExecutionContext | undefined);
