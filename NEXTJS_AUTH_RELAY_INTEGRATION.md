# Next.js 转发与 auth.json 加密上传对接规格

## 1. 客户端配置

程序启动时在 exe 同级目录生成：

```json
{
  "server_url": "https://your-domain.example/api/codex-relay",
  "api_key": "填入你的转发服务器密钥"
}
```

要求：

- 文件名固定：`relay_server_key.json`
- `server_url` 指向 Next.js 转发接口
- `api_key` 与服务端 `CODEX_RELAY_API_KEY` 一致
- 真实文件不得提交仓库

## 2. 客户端请求策略

顺序：

1. 直连官方接口
2. WinHTTP 未取得响应时，调用转发服务器
3. 已取得 HTTP 响应时不走转发服务器，包括 `401`、`403`、`5xx`

转发请求：

```http
POST /api/codex-relay
Authorization: Bearer <api_key>
X-Codex-Relay-Key: <api_key>
Content-Type: application/json
```

```json
{
  "method": "GET",
  "url": "https://chatgpt.com/backend-api/wham/usage",
  "headers": "Authorization: Bearer ...\r\nChatGPT-Account-ID: ...\r\nUser-Agent: CodexLimitFloat/1.0\r\n",
  "body": ""
}
```

服务端返回二选一。

原样返回：

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"plan_type":"plus","rate_limit":{}}
```

包装返回：

```json
{
  "status": 200,
  "body": "{\"plan_type\":\"plus\",\"rate_limit\":{}}"
}
```

## 3. 环境变量

```bash
CODEX_RELAY_API_KEY=""
AUTH_WRAP_KEY_BASE64=""
HANDSHAKE_TTL_SECONDS="120"
```

`AUTH_WRAP_KEY_BASE64`：32 字节随机值的 base64。

## 4. `/api/codex-relay`

`app/api/codex-relay/route.ts`

```ts
import { NextRequest, NextResponse } from "next/server";

const allowedHosts = new Set(["chatgpt.com", "auth.openai.com"]);

function checkRelayKey(req: NextRequest) {
  const expected = process.env.CODEX_RELAY_API_KEY;
  const auth = req.headers.get("authorization") || "";
  const key = req.headers.get("x-codex-relay-key") || "";
  return expected && (auth === `Bearer ${expected}` || key === expected);
}

function parseHeaderLines(raw: string) {
  const headers = new Headers();
  for (const line of raw.split(/\r?\n/)) {
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    const name = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (!name || /^(host|content-length|connection)$/i.test(name)) continue;
    headers.set(name, value);
  }
  return headers;
}

export async function POST(req: NextRequest) {
  if (!checkRelayKey(req)) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }

  const input = await req.json() as {
    method?: string;
    url?: string;
    headers?: string;
    body?: string;
  };

  const method = (input.method || "GET").toUpperCase();
  const target = new URL(input.url || "");

  if (!allowedHosts.has(target.hostname)) {
    return NextResponse.json({ error: "target_not_allowed" }, { status: 400 });
  }

  const upstream = await fetch(target.toString(), {
    method,
    headers: parseHeaderLines(input.headers || ""),
    body: method === "GET" || method === "HEAD" ? undefined : (input.body || ""),
    cache: "no-store",
  });

  return new NextResponse(await upstream.text(), {
    status: upstream.status,
    headers: {
      "content-type": upstream.headers.get("content-type") || "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}
```

硬性约束：

- 只允许 `chatgpt.com`、`auth.openai.com`
- 禁止转发 `Host`、`Content-Length`、`Connection`
- 禁止记录 token、请求体、响应体
- 仅部署 HTTPS

## 5. auth.json 上传协议

算法：

- ECDH：P-256
- KDF：HKDF-SHA256
- 加密：AES-256-GCM
- IV：12 字节随机值
- AAD：`handshakeId.clientNonce.serverNonce`

HKDF 参数：

- IKM：ECDH shared secret
- salt：`clientNonce || serverNonce`
- info：`codex-auth-upload-v1`
- length：32

## 6. `/api/auth/handshake`

请求：

```json
{
  "clientPublicJwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "",
    "y": "",
    "ext": true
  },
  "clientNonce": ""
}
```

响应：

```json
{
  "handshakeId": "",
  "serverPublicJwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "",
    "y": "",
    "ext": true
  },
  "serverNonce": "",
  "expiresAt": ""
}
```

握手记录：

```ts
type HandshakeRecord = {
  handshakeId: string;
  serverPrivateJwk: JsonWebKey;
  clientPublicJwk: JsonWebKey;
  clientNonce: string;
  serverNonce: string;
  expiresAt: string;
  used: boolean;
};
```

要求：

- TTL 默认 120 秒
- 一次性使用
- 上传成功或失败后删除

## 7. `/api/auth/upload`

请求：

```json
{
  "handshakeId": "",
  "clientNonce": "",
  "serverNonce": "",
  "iv": "",
  "ciphertext": ""
}
```

服务端步骤：

1. 读取握手记录
2. 校验 TTL、`used`、`clientNonce`、`serverNonce`
3. ECDH 派生 shared secret
4. HKDF 派生 AES key
5. AES-256-GCM 解密
6. 校验 auth JSON
7. 使用 `AUTH_WRAP_KEY_BASE64` 加密落库
8. 删除握手记录

auth JSON 校验：

```ts
type CodexAuthJson = {
  auth_mode: "chatgpt";
  tokens?: {
    id_token?: string;
    access_token?: string;
    refresh_token?: string;
    account_id?: string;
  };
  id_token?: string;
  access_token?: string;
  refresh_token?: string;
  account_id?: string;
};
```

至少要求：

- `auth_mode === "chatgpt"`
- `access_token` 非空

## 8. 落库格式

```ts
type StoredAuth = {
  id: string;
  version: 1;
  algorithm: "AES-256-GCM";
  key_id: "env:AUTH_WRAP_KEY_BASE64:v1";
  iv: string;
  tag: string;
  ciphertext: string;
  created_at: string;
  updated_at: string;
};
```

服务端加密：

```ts
import crypto from "node:crypto";

function wrapKey() {
  const key = Buffer.from(process.env.AUTH_WRAP_KEY_BASE64 || "", "base64");
  if (key.length !== 32) throw new Error("invalid AUTH_WRAP_KEY_BASE64");
  return key;
}

export function encryptForStorage(plainText: string) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", wrapKey(), iv);
  cipher.setAAD(Buffer.from("codex-auth-json-storage-v1"));
  const ciphertext = Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    algorithm: "AES-256-GCM",
    key_id: "env:AUTH_WRAP_KEY_BASE64:v1",
    iv: iv.toString("base64url"),
    tag: tag.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
  };
}
```

服务端解密：

```ts
export function decryptFromStorage(record: { iv: string; tag: string; ciphertext: string }) {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    wrapKey(),
    Buffer.from(record.iv, "base64url")
  );
  decipher.setAAD(Buffer.from("codex-auth-json-storage-v1"));
  decipher.setAuthTag(Buffer.from(record.tag, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(record.ciphertext, "base64url")),
    decipher.final(),
  ]).toString("utf8");
}
```

## 9. 对接步骤

1. 部署 Next.js HTTPS 服务
2. 配置 `CODEX_RELAY_API_KEY`
3. 配置 `AUTH_WRAP_KEY_BASE64`
4. 实现 `/api/codex-relay`
5. 实现 `/api/auth/handshake`
6. 实现 `/api/auth/upload`
7. 启动本项目生成 `relay_server_key.json`
8. 填入 `server_url` 与 `api_key`
9. 启动客户端验证官方优先、失败转发

## 10. 验收项

- 无密钥访问 `/api/codex-relay` 返回 `401`
- 非白名单目标返回 `400`
- 转发响应与上游 status/body 一致
- 浏览器上传包体不含 token 明文
- 数据库不含 token 明文
- 删除 `AUTH_WRAP_KEY_BASE64` 后无法解密历史记录
