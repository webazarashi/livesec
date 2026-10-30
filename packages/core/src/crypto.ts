/**
 * WebCrypto だけを使う暗号ユーティリティ（Workers・ブラウザ・Node 共通）。
 * - Slack Webhook URL の暗号化保存（AES-GCM、12章）
 * - プロジェクトのAPIトークンの発行とハッシュ化
 */

function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function fromBase64(b64: string): Uint8Array<ArrayBuffer> {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function importKey(keyB64: string): Promise<CryptoKey> {
  const raw = fromBase64(keyB64);
  if (raw.length !== 32) throw new Error("暗号鍵は32バイト（base64）で指定してください");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

/** `v1.<iv>.<ciphertext>`（base64）。aad にテナントIDなどを入れて、別の行への付け替えを防ぐ */
export async function encryptSecret(plaintext: string, keyB64: string, aad: string): Promise<string> {
  const key = await importKey(keyB64);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(aad) },
    key,
    new TextEncoder().encode(plaintext),
  );
  return `v1.${toBase64(iv)}.${toBase64(new Uint8Array(ct))}`;
}

export async function decryptSecret(payload: string, keyB64: string, aad: string): Promise<string> {
  const [ver, ivB64, ctB64] = payload.split(".");
  if (ver !== "v1" || !ivB64 || !ctB64) throw new Error("暗号文の形式が不正です");
  const key = await importKey(keyB64);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(ivB64), additionalData: new TextEncoder().encode(aad) },
    key,
    fromBase64(ctB64),
  );
  return new TextDecoder().decode(pt);
}

export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export const API_TOKEN_PREFIX = "ichiji_";

/** プロジェクトごとのAPIトークン。保存するのはハッシュだけ */
export async function generateApiToken(): Promise<{ token: string; hash: string; hint: string }> {
  const token = `${API_TOKEN_PREFIX}${toBase64Url(crypto.getRandomValues(new Uint8Array(32)))}`;
  return { token, hash: await sha256Hex(token), hint: `${token.slice(0, 11)}…${token.slice(-4)}` };
}

export function randomId(bytes = 16): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(bytes)));
}

/** タイミング攻撃を避ける文字列比較 */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
