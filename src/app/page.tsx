"use client";

import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  FileJson,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  UploadCloud,
} from "lucide-react";
import { useMemo, useRef, useState } from "react";

type UploadState = "idle" | "working" | "success" | "error";

type HandshakeResponse = {
  handshakeId: string;
  serverPublicJwk: JsonWebKey;
  serverNonce: string;
  expiresAt: string;
};

type UploadResponse = {
  ok: true;
  id: string;
  relay_api_key: string;
  server_url: string;
  updated_at: string;
};

const encoder = new TextEncoder();

function toBase64Url(bytes: ArrayBuffer | Uint8Array) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (const byte of view) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function fromBase64Url(value: string) {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function concatBytes(left: Uint8Array, right: Uint8Array) {
  const combined = new Uint8Array(left.length + right.length);
  combined.set(left);
  combined.set(right, left.length);
  return combined;
}

function validateAuthJsonText(text: string) {
  const parsed = JSON.parse(text) as {
    auth_mode?: unknown;
    access_token?: unknown;
    tokens?: { access_token?: unknown };
  };
  const accessToken =
    typeof parsed.access_token === "string"
      ? parsed.access_token
      : parsed.tokens?.access_token;

  if (parsed.auth_mode !== "chatgpt" || typeof accessToken !== "string" || !accessToken) {
    throw new Error("auth.json 必须包含 auth_mode=chatgpt 和 access_token");
  }
}

function readFileWithProgress(
  file: File,
  onProgress: (percent: number) => void,
) {
  return new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onprogress = (event) => {
      if (event.lengthComputable) {
        onProgress(Math.round((event.loaded / event.total) * 50));
      }
    };
    reader.onerror = () => reject(new Error("无法读取文件"));
    reader.onload = () => {
      onProgress(50);
      resolve(String(reader.result || ""));
    };
    reader.readAsText(file);
  });
}

async function postJson<T>(path: string, body: Record<string, unknown>) {
  const response = await fetch(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
    cache: "no-store",
  });

  const data = (await response.json().catch(() => ({}))) as T & {
    error?: string;
  };
  if (!response.ok) {
    throw new Error(data.error || `请求失败：${response.status}`);
  }

  return data;
}

async function encryptAuthJson(
  plainText: string,
  handshake: HandshakeResponse,
  clientNonce: string,
  clientPrivateKey: CryptoKey,
) {
  const serverPublicKey = await crypto.subtle.importKey(
    "jwk",
    handshake.serverPublicJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const sharedSecret = await crypto.subtle.deriveBits(
    { name: "ECDH", public: serverPublicKey },
    clientPrivateKey,
    256,
  );
  const hkdfKey = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, [
    "deriveKey",
  ]);
  const salt = concatBytes(
    fromBase64Url(clientNonce),
    fromBase64Url(handshake.serverNonce),
  );
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info: encoder.encode("codex-auth-upload-v1"),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: encoder.encode(
        `${handshake.handshakeId}.${clientNonce}.${handshake.serverNonce}`,
      ),
    },
    aesKey,
    encoder.encode(plainText),
  );

  return {
    iv: toBase64Url(iv),
    ciphertext: toBase64Url(ciphertext),
  };
}

export default function Home() {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [state, setState] = useState<UploadState>("idle");
  const [progress, setProgress] = useState(0);
  const [phase, setPhase] = useState("等待选择文件");
  const [message, setMessage] = useState("");
  const [relayConfig, setRelayConfig] = useState<UploadResponse | null>(null);

  const canUpload = useMemo(
    () => Boolean(selectedFile && state !== "working"),
    [selectedFile, state],
  );

  const relayServerKeyJson = useMemo(() => {
    if (!relayConfig) {
      return "";
    }

    return JSON.stringify(
      {
        server_url: relayConfig.server_url,
        api_key: relayConfig.relay_api_key,
      },
      null,
      2,
    );
  }, [relayConfig]);

  async function uploadSelectedFile(file: File) {
    setState("working");
    setProgress(0);
    setMessage("");
    setRelayConfig(null);

    try {
      setPhase("上传文件");
      const plainText = await readFileWithProgress(file, setProgress);
      validateAuthJsonText(plainText);

      setPhase("生成握手密钥");
      setProgress(58);
      const clientKeyPair = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"],
      );
      const clientPublicJwk = await crypto.subtle.exportKey(
        "jwk",
        clientKeyPair.publicKey,
      );
      const clientNonce = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));

      setPhase("建立安全握手");
      setProgress(68);
      const handshake = await postJson<HandshakeResponse>("/api/auth/handshake", {
        clientPublicJwk,
        clientNonce,
      });

      setPhase("浏览器端加密");
      setProgress(80);
      const encrypted = await encryptAuthJson(
        plainText,
        handshake,
        clientNonce,
        clientKeyPair.privateKey,
      );

      setPhase("提交密文");
      setProgress(92);
      const upload = await postJson<UploadResponse>("/api/auth/upload", {
        handshakeId: handshake.handshakeId,
        clientNonce,
        serverNonce: handshake.serverNonce,
        iv: encrypted.iv,
        ciphertext: encrypted.ciphertext,
      });

      setPhase("完成");
      setProgress(100);
      setState("success");
      setRelayConfig(upload);
      setMessage("auth.json 已加密上传，服务端已生成 relay key。");
    } catch (error) {
      setState("error");
      setMessage(error instanceof Error ? error.message : "上传失败");
    }
  }

  function handleFileChange(file: File | null) {
    setSelectedFile(file);
    setState("idle");
    setProgress(0);
    setPhase(file ? "文件已选择" : "等待选择文件");
    setMessage("");
    setRelayConfig(null);
  }

  async function copyRelayConfig() {
    if (!relayServerKeyJson) {
      return;
    }

    await navigator.clipboard.writeText(relayServerKeyJson);
    setMessage("relay_server_key.json 内容已复制。");
  }

  return (
    <main className="min-h-screen overflow-x-hidden bg-[#f6f7f4] text-zinc-950">
      <div className="mx-auto flex min-h-screen w-[calc(100vw-40px)] max-w-full flex-col py-8 sm:w-full sm:px-8 lg:max-w-6xl lg:px-10">
        <header className="mb-8 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex size-11 items-center justify-center rounded-lg bg-emerald-600 text-white shadow-sm">
              <LockKeyhole size={22} aria-hidden />
            </div>
            <div>
              <p className="text-sm font-medium text-zinc-500">Codex Relay</p>
              <h1 className="text-xl font-semibold tracking-normal text-zinc-950 sm:text-2xl">
                auth.json 加密上传
              </h1>
            </div>
          </div>
          <div className="hidden items-center gap-2 rounded-full border border-zinc-200 bg-white px-4 py-2 text-sm font-medium text-zinc-600 shadow-sm sm:flex">
            <ShieldIcon />
            本地加密
          </div>
        </header>

        <section className="grid w-full min-w-0 max-w-full flex-1 grid-cols-1 items-center gap-6 lg:grid-cols-[minmax(0,1fr)_360px]">
          <div className="w-full min-w-0 max-w-full rounded-lg border border-zinc-200 bg-white p-5 shadow-sm sm:p-7">
            <div className="mb-6 grid gap-4">
              <input
                ref={fileInputRef}
                type="file"
                accept=".json,application/json"
                className="sr-only"
                onChange={(event) => handleFileChange(event.target.files?.[0] || null)}
              />

              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="flex min-h-44 w-full flex-col items-center justify-center gap-4 rounded-lg border border-dashed border-zinc-300 bg-[#fafaf7] px-5 py-8 text-center transition hover:border-emerald-600 hover:bg-emerald-50 focus:outline-none focus:ring-4 focus:ring-emerald-100"
              >
                <span className="flex size-14 items-center justify-center rounded-lg bg-zinc-950 text-white">
                  <UploadCloud size={26} aria-hidden />
                </span>
                <span className="grid gap-1">
                  <span className="break-all text-lg font-semibold text-zinc-950">
                    {selectedFile ? selectedFile.name : "选择 auth.json"}
                  </span>
                  <span className="text-sm text-zinc-500">
                    {selectedFile
                      ? `${(selectedFile.size / 1024).toFixed(1)} KB`
                      : "只接受 JSON 文件"}
                  </span>
                </span>
              </button>
            </div>

            <div className="mb-6">
              <div className="mb-2 flex items-center justify-between text-sm">
                <span className="font-medium text-zinc-700">{phase}</span>
                <span className="font-semibold text-zinc-950">{progress}%</span>
              </div>
              <div className="h-3 overflow-hidden rounded-full bg-zinc-200">
                <div
                  className="h-full rounded-full bg-emerald-600 transition-all duration-300"
                  style={{ width: `${progress}%` }}
                />
              </div>
              <div className="mt-2 flex flex-col gap-1 text-xs font-medium text-zinc-500 sm:flex-row sm:items-center sm:justify-between">
                <span>0-50% 文件上传</span>
                <span>50-100% 握手、加密、落库</span>
              </div>
            </div>

            {message ? (
              <div
                className={`mb-5 flex items-start gap-3 rounded-md border px-4 py-3 text-sm ${
                  state === "success"
                    ? "border-emerald-200 bg-emerald-50 text-emerald-900"
                    : "border-red-200 bg-red-50 text-red-900"
                }`}
              >
                {state === "success" ? (
                  <CheckCircle2 className="mt-0.5 shrink-0" size={18} aria-hidden />
                ) : (
                  <AlertTriangle className="mt-0.5 shrink-0" size={18} aria-hidden />
                )}
                <span>{message}</span>
              </div>
            ) : null}

            {relayConfig ? (
              <div className="mb-5 grid gap-3 rounded-lg border border-emerald-200 bg-emerald-50 p-4">
                <div className="flex items-center justify-between gap-3">
                  <span className="flex items-center gap-2 text-sm font-semibold text-emerald-900">
                    <KeyRound size={16} aria-hidden />
                    服务端生成的 relay key
                  </span>
                  <button
                    type="button"
                    onClick={copyRelayConfig}
                    className="flex h-9 shrink-0 items-center gap-2 rounded-md bg-emerald-600 px-3 text-sm font-semibold text-white transition hover:bg-emerald-700"
                  >
                    <Copy size={15} aria-hidden />
                    复制
                  </button>
                </div>
                <pre className="max-h-44 overflow-auto whitespace-pre-wrap break-all rounded-md bg-white p-3 text-xs leading-5 text-zinc-700">
                  {relayServerKeyJson}
                </pre>
              </div>
            ) : null}

            <button
              type="button"
              disabled={!canUpload}
              onClick={() => selectedFile && uploadSelectedFile(selectedFile)}
              className="flex h-12 w-full items-center justify-center gap-2 rounded-md bg-zinc-950 px-5 text-base font-semibold text-white transition hover:bg-zinc-800 disabled:cursor-not-allowed disabled:bg-zinc-300 disabled:text-zinc-500"
            >
              {state === "working" ? (
                <LoaderCircle className="animate-spin" size={19} aria-hidden />
              ) : (
                <UploadCloud size={19} aria-hidden />
              )}
              {state === "working" ? "处理中" : "加密上传"}
            </button>
          </div>

          <aside className="min-w-0 rounded-lg border border-zinc-200 bg-[#10201a] p-5 text-white shadow-sm sm:p-6">
            <div className="mb-5 flex size-12 items-center justify-center rounded-lg bg-emerald-500 text-[#10201a]">
              <FileJson size={24} aria-hidden />
            </div>
            <h2 className="mb-3 text-xl font-semibold tracking-normal">上传流程</h2>
            <ol className="grid gap-4 text-sm text-emerald-50">
              <li className="flex gap-3">
                <StepBadge>1</StepBadge>
                <span>选择本机 auth.json，读取进度计入前 50%。</span>
              </li>
              <li className="flex gap-3">
                <StepBadge>2</StepBadge>
                <span>浏览器生成 ECDH 密钥并与服务端握手。</span>
              </li>
              <li className="flex gap-3">
                <StepBadge>3</StepBadge>
                <span>使用 AES-GCM 加密后提交密文。</span>
              </li>
              <li className="flex gap-3">
                <StepBadge>4</StepBadge>
                <span>服务端落库后生成 relay key 并返回。</span>
              </li>
            </ol>
          </aside>
        </section>
      </div>
    </main>
  );
}

function StepBadge({ children }: { children: React.ReactNode }) {
  return (
    <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-emerald-400 text-xs font-bold text-[#10201a]">
      {children}
    </span>
  );
}

function ShieldIcon() {
  return <CheckCircle2 size={16} className="text-emerald-600" aria-hidden />;
}
