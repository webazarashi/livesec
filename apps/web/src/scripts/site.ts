/**
 * 全ページ共通のブラウザ側スクリプト。
 * ページはエッジキャッシュされるので、ログイン状態などの個人の情報はここで取得して差し替える。
 */

// ---------- ログイン状態（ヘッダー） ----------
export interface MemberInfo {
  user: { email: string } | null;
  isAdmin?: boolean;
}

/** ログイン状態。会員のときだけ個人の情報（私の環境など）を取りに行くために共有する */
export const member: Promise<MemberInfo> = fetch("/api/me", { credentials: "same-origin" })
  .then((res) => res.json() as Promise<MemberInfo>)
  .catch(() => ({ user: null }));

async function refreshMemberNav(): Promise<void> {
  const nav = document.querySelector("[data-member-nav]");
  const data = await member;
  if (!nav || !data.user) return;
  nav.querySelectorAll<HTMLElement>("[data-guest]").forEach((el) => (el.hidden = true));
  nav.querySelectorAll<HTMLElement>("[data-member]").forEach((el) => (el.hidden = false));
  if (data.isAdmin) nav.querySelectorAll<HTMLElement>("[data-admin]").forEach((el) => (el.hidden = false));
  document.documentElement.dataset.member = "1";
}

// ---------- クリップボード ----------
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    return ok;
  }
}

function flash(button: HTMLElement, label: string): void {
  const prev = button.textContent;
  button.textContent = label;
  setTimeout(() => (button.textContent = prev), 1600);
}

document.addEventListener("click", async (e) => {
  const target = e.target as HTMLElement | null;
  const codeBtn = target?.closest<HTMLElement>("[data-copy-code]");
  if (codeBtn) {
    const code = codeBtn.closest(".codeblock")?.querySelector("code")?.textContent ?? "";
    flash(codeBtn, (await copyText(code)) ? "コピーしました" : "コピーできません");
    return;
  }
  const copyBtn = target?.closest<HTMLElement>("[data-copy]");
  if (copyBtn) {
    const value = copyBtn.dataset.copy === "url" ? location.href.split("#")[0]! : (copyBtn.dataset.copy ?? "");
    flash(copyBtn, (await copyText(value)) ? "コピーしました" : "コピーできません");
  }
});

// ---------- ☆保存（ブラウザに保存。ログイン不要） ----------
const SAVE_KEY = "ichiji:saved";

export interface SavedArticle {
  url: string;
  title: string;
  cve: string;
  rank: string;
  savedAt: string;
}

export function loadSaved(): SavedArticle[] {
  try {
    const raw = localStorage.getItem(SAVE_KEY);
    const list = raw ? (JSON.parse(raw) as SavedArticle[]) : [];
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

function storeSaved(list: SavedArticle[]): void {
  try {
    localStorage.setItem(SAVE_KEY, JSON.stringify(list.slice(0, 200)));
  } catch {
    // 保存できない環境（プライベートモード等）
  }
}

function renderSaveButtons(): void {
  const saved = new Set(loadSaved().map((s) => s.url));
  document.querySelectorAll<HTMLButtonElement>("[data-save]").forEach((btn) => {
    const on = saved.has(btn.dataset.saveUrl ?? "");
    btn.setAttribute("aria-pressed", on ? "true" : "false");
    btn.querySelector("[data-save-label]")!.textContent = on ? "保存済み" : "保存する";
    btn.querySelector("[data-save-star]")!.textContent = on ? "★" : "☆";
  });
}

document.addEventListener("click", (e) => {
  const btn = (e.target as HTMLElement | null)?.closest<HTMLButtonElement>("[data-save]");
  if (!btn) return;
  const url = btn.dataset.saveUrl ?? "";
  const list = loadSaved();
  const idx = list.findIndex((s) => s.url === url);
  if (idx >= 0) list.splice(idx, 1);
  else list.unshift({ url, title: btn.dataset.saveTitle ?? "", cve: btn.dataset.saveCve ?? "", rank: btn.dataset.saveRank ?? "", savedAt: new Date().toISOString() });
  storeSaved(list);
  renderSaveButtons();
});

// ---------- タブ（POPULAR の24時間／月間） ----------
document.querySelectorAll<HTMLElement>("[data-tabs]").forEach((root) => {
  const tabs = [...root.querySelectorAll<HTMLButtonElement>("[role=tab]")];
  tabs.forEach((tab) =>
    tab.addEventListener("click", () => {
      tabs.forEach((t) => {
        const selected = t === tab;
        t.setAttribute("aria-selected", selected ? "true" : "false");
        const panel = document.getElementById(t.getAttribute("aria-controls") ?? "");
        if (panel) panel.hidden = !selected;
      });
    }),
  );
});

// ---------- 目次（モバイル） ----------
document.querySelector("[data-toc-open]")?.addEventListener("click", () => {
  const dialog = document.querySelector<HTMLDialogElement>("[data-toc-dialog]");
  dialog?.showModal();
});
document.querySelector("[data-toc-dialog]")?.addEventListener("click", (e) => {
  const dialog = e.currentTarget as HTMLDialogElement;
  if ((e.target as HTMLElement).closest("a") || e.target === dialog) dialog.close();
});

renderSaveButtons();
void refreshMemberNav();
