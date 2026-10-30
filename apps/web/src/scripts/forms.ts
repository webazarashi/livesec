/** 会員画面・管理画面の小さなフォーム用ヘルパー */
export async function api<T = unknown>(url: string, init: { method?: string; body?: unknown; form?: FormData } = {}): Promise<{ ok: boolean; status: number; data: T }> {
  const headers: Record<string, string> = {};
  let body: BodyInit | undefined;
  if (init.form) body = init.form;
  else if (init.body !== undefined) {
    headers["content-type"] = "application/json";
    body = JSON.stringify(init.body);
  }
  const res = await fetch(url, { method: init.method ?? (body ? "POST" : "GET"), headers, body, credentials: "same-origin" });
  const text = await res.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { error: text };
  }
  return { ok: res.ok, status: res.status, data: data as T };
}

export function errorMessage(data: unknown, fallback = "エラーが発生しました"): string {
  if (data && typeof data === "object") {
    const d = data as { error?: unknown; message?: unknown; code?: unknown };
    if (typeof d.message === "string") return translate(d.message, d.code);
    if (typeof d.error === "string") return d.error;
  }
  return fallback;
}

/** Better Auth の主なエラーを日本語にする */
function translate(message: string, code: unknown): string {
  const map: Record<string, string> = {
    INVALID_EMAIL_OR_PASSWORD: "メールアドレスまたはパスワードが違います",
    USER_ALREADY_EXISTS: "このメールアドレスはすでに登録されています",
    USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL: "このメールアドレスはすでに登録されています",
    PASSWORD_TOO_SHORT: "パスワードは10文字以上にしてください",
    PASSWORD_TOO_LONG: "パスワードが長すぎます",
    INVALID_EMAIL: "メールアドレスの形式が正しくありません",
    INVALID_CODE: "確認コードが違います",
    INVALID_TWO_FACTOR_COOKIE: "時間切れです。もう一度ログインしてください",
    INVALID_PASSWORD: "パスワードが違います",
    TOO_MANY_REQUESTS: "試行回数が多すぎます。しばらく待ってからお試しください",
  };
  if (typeof code === "string" && map[code]) return map[code]!;
  if (/too many/i.test(message)) return map.TOO_MANY_REQUESTS!;
  return message;
}

export function setStatus(el: Element | null, message: string, kind: "ok" | "error" | "info" = "info"): void {
  if (!el) return;
  el.textContent = message;
  el.className = `form-status form-status--${kind}`;
}

export function safeNext(value: string | null, fallback = "/app/"): string {
  return value && value.startsWith("/") && !value.startsWith("//") ? value : fallback;
}
