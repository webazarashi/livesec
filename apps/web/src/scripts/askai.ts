import {
  ASK_TARGETS,
  buildAskPrompt,
  getPreset,
  MY_ENVIRONMENT_TEMPLATE,
  planAsk,
  type AskArticleData,
  type AskTarget,
} from "@ichiji/core/askai";
import { copyText } from "./site";

/**
 * Ask AI（6章）。プロンプトはブラウザ側で組み立て、自社のサーバには送らない。
 * 会員は「私の環境」をAPIから取得して差し込む（記事ページはキャッシュされるのでHTMLには入れない）。
 */
const root = document.getElementById("ask-ai");
const dataEl = document.getElementById("askai-data");

if (root && dataEl) {
  const data = JSON.parse(dataEl.textContent ?? "{}") as AskArticleData;
  const envInput = root.querySelector<HTMLTextAreaElement>("[data-askai-env]")!;
  const envHint = root.querySelector<HTMLElement>("[data-askai-env-hint]")!;
  const question = root.querySelector<HTMLTextAreaElement>("[data-askai-question]")!;
  const preview = root.querySelector<HTMLElement>("[data-askai-preview]")!;
  const status = root.querySelector<HTMLElement>("[data-askai-status]")!;
  const presets = [...root.querySelectorAll<HTMLButtonElement>("[data-preset]")];

  const envText = () => {
    const v = envInput.value.trim();
    return v === MY_ENVIRONMENT_TEMPLATE ? "" : v;
  };
  const questionText = () => question.value.trim() || getPreset("need")!.question;

  const updatePreview = () => {
    preview.textContent = buildAskPrompt(data, envText(), questionText());
  };

  const selectPreset = (key: string) => {
    const preset = getPreset(key);
    if (!preset) return;
    question.value = preset.question;
    presets.forEach((b) => b.setAttribute("aria-pressed", b.dataset.preset === key ? "true" : "false"));
    updatePreview();
  };

  presets.forEach((b) => b.addEventListener("click", () => selectPreset(b.dataset.preset!)));
  question.addEventListener("input", () => {
    presets.forEach((b) => b.setAttribute("aria-pressed", "false"));
    updatePreview();
  });
  envInput.addEventListener("input", updatePreview);

  const say = (message: string) => {
    status.textContent = message;
  };

  const open = (url: string): boolean => {
    const w = window.open(url, "_blank");
    if (w) {
      w.opener = null;
      return true;
    }
    return false;
  };

  root.querySelectorAll<HTMLButtonElement>("[data-ask-target]").forEach((btn) =>
    btn.addEventListener("click", async () => {
      const target = btn.dataset.askTarget as AskTarget;
      const plan = planAsk(target, data, envText(), questionText());
      const label = ASK_TARGETS[target].label;
      if (plan.mode === "url") {
        if (!open(plan.url)) say(`ポップアップがブロックされました。プロンプトをコピーして${label}に貼り付けてください。`);
        else say(plan.trimmedExcerpt ? `${label}を開きました（URLの長さの都合で本文の抜粋を短くしています）。` : `${label}を開きました。`);
        return;
      }
      const copied = await copyText(plan.prompt);
      const reason = target === "gemini" ? "Geminiは自動入力に対応していないため" : "プロンプトが長いため";
      if (!copied) {
        say("コピーできませんでした。「AIに渡すプロンプトを確認する」から手動でコピーしてください。");
        return;
      }
      if (open(plan.url)) say(`${reason}、プロンプトをコピーしました。${label}の入力欄に貼り付けて送信してください。`);
      else {
        status.innerHTML = "";
        status.appendChild(document.createTextNode(`${reason}、プロンプトをコピーしました。`));
        const a = document.createElement("a");
        a.href = plan.url;
        a.target = "_blank";
        a.rel = "noopener";
        a.textContent = `${label}を開く →`;
        status.appendChild(a);
      }
    }),
  );

  root.querySelector("[data-ask-copy]")?.addEventListener("click", async () => {
    const prompt = buildAskPrompt(data, envText(), questionText());
    say((await copyText(prompt)) ? "プロンプトをコピーしました。お使いのAIに貼り付けてください。" : "コピーできませんでした。");
  });

  // 会員なら「私の環境」をAPIから取得して差し込む
  void (async () => {
    try {
      const res = await fetch("/api/me/environment", { credentials: "same-origin" });
      if (!res.ok) return;
      const body = (await res.json()) as { text: string };
      document.documentElement.dataset.member = "1";
      if (body.text.trim()) {
        envInput.value = body.text;
        envHint.innerHTML = "";
        envHint.appendChild(document.createTextNode("会員設定の「私の環境」を読み込みました。送る前に確認・編集できます（"));
        const link = document.createElement("a");
        link.href = "/app/settings/";
        link.textContent = "設定を変更";
        envHint.appendChild(link); envHint.appendChild(document.createTextNode("）。"));
      } else {
        envHint.innerHTML = "";
        envHint.appendChild(document.createTextNode("会員設定で「私の環境」を保存すると、次回から自動で入ります（"));
        const link = document.createElement("a");
        link.href = "/app/settings/";
        link.textContent = "設定する";
        envHint.appendChild(link); envHint.appendChild(document.createTextNode("）。"));
      }
      updatePreview();
    } catch {
      // 非会員・オフライン
    }
  })();

  // Slack・ダッシュボードからは ?ask=need のようにプリセットを選んだ状態で開く（6-3）
  const fromUrl = new URLSearchParams(location.search).get("ask");
  if (fromUrl && getPreset(fromUrl)) {
    selectPreset(fromUrl);
    if (location.hash === "#ask-ai") root.scrollIntoView();
  } else {
    updatePreview();
  }
}
