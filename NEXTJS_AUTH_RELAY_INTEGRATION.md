# Next.js 转发与 auth.json 加密上传对接规格

## 1. 客户端配置

程序启动时在 exe 同级目录生成：

```json
{
  "server_url": "https://your-domain.example/api/codex-relay",
  "api_key": "填入上传接口返回的 relay_api_key",
  "one_way_key": "填入上传接口额外返回的 one_way_key"
}
```

要求：

- 文件名固定：`relay_server_key.json`
- `server_url` 指向 Next.js 转发接口
- `api_key` 使用服务端返回的 `relay_api_key`
- `one_way_key` 是额外返回字段，不替代 `api_key`
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

用量请求失败淘汰：

- 仅适用于 `https://chatgpt.com/backend-api/wham/usage`
- 同一个 `relay_api_key` 指纹在 24 小时内失败 2 次时，返回自定义 HTTP 状态码 `498`
- 返回 `498` 前必须精准删除该指纹对应的 Redis auth 记录、索引集合成员和失败计数
- 第 1 次失败仍按上游失败结果返回

## 3. 环境变量

```bash
AUTH_WRAP_KEY_BASE64=""
HANDSHAKE_TTL_SECONDS="120"
```

`AUTH_WRAP_KEY_BASE64`：32 字节随机值的 base64。

## 4. `/api/codex-relay`

`app/api/codex-relay/route.ts`

```ts
import { NextRequest, NextResponse } from "next/server";
import { authenticateRelayKey } from "@/lib/relay-auth";

const allowedHosts = new Set(["chatgpt.com", "auth.openai.com"]);

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
  if (!(await authenticateRelayKey(req))) {
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
- 用量请求 24 小时内失败 2 次后返回 `498` 并删除对应 Redis 记录

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
7. 生成 `relay_api_key` 与 `one_way_key`
8. 只用 `relay_api_key` 的 SHA-256 指纹作为 Redis 记录 ID
9. 使用 `AUTH_WRAP_KEY_BASE64` 与 `one_way_key` 派生存储密钥后加密落库
10. 返回 `relay_api_key` 和 `one_way_key`
11. 删除握手记录

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
  version: 2;
  algorithm: "AES-256-GCM";
  key_id: "env:AUTH_WRAP_KEY_BASE64+one_way_key:v2";
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

const storageInfo = Buffer.from("codex-auth-json-storage-v2");
const storageAad = Buffer.from("codex-auth-json-storage-v2");

function wrapKey() {
  const key = Buffer.from(process.env.AUTH_WRAP_KEY_BASE64 || "", "base64");
  if (key.length !== 32) throw new Error("invalid AUTH_WRAP_KEY_BASE64");
  return key;
}

function deriveStorageKey(oneWayKey: string) {
  const salt = crypto.createHash("sha256").update(oneWayKey, "utf8").digest();
  return Buffer.from(crypto.hkdfSync("sha256", wrapKey(), salt, storageInfo, 32));
}

export function encryptForStorage(plainText: string, oneWayKey: string) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", deriveStorageKey(oneWayKey), iv);
  cipher.setAAD(storageAad);
  const ciphertext = Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    algorithm: "AES-256-GCM",
    key_id: "env:AUTH_WRAP_KEY_BASE64+one_way_key:v2",
    iv: iv.toString("base64url"),
    tag: tag.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
  };
}
```

服务端解密：

```ts
export function decryptFromStorage(
  record: { iv: string; tag: string; ciphertext: string },
  oneWayKey: string
) {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    deriveStorageKey(oneWayKey),
    Buffer.from(record.iv, "base64url")
  );
  decipher.setAAD(storageAad);
  decipher.setAuthTag(Buffer.from(record.tag, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(record.ciphertext, "base64url")),
    decipher.final(),
  ]).toString("utf8");
}
```

## 9. 对接步骤

1. 部署 Next.js HTTPS 服务
2. 配置 `AUTH_WRAP_KEY_BASE64`
3. 实现 `/api/codex-relay`
4. 实现 `/api/auth/handshake`
5. 实现 `/api/auth/upload`
6. 启动本项目生成 `relay_server_key.json`
7. 填入 `server_url`、`api_key` 与 `one_way_key`，其中 `api_key` 使用上传接口返回的 `relay_api_key`
8. 启动客户端验证官方优先、失败转发

## 10. 验收项

- 无密钥访问 `/api/codex-relay` 返回 `401`
- 非白名单目标返回 `400`
- 转发响应与上游 status/body 一致
- 用量请求同一 key 24 小时内第 2 次失败返回 `498`
- 返回 `498` 时只删除当前 key 指纹对应的 Redis auth 记录
- 浏览器上传包体不含 token 明文
- 数据库不含 token 明文
- 数据库不含 `relay_api_key` 明文
- 数据库不含 `one_way_key` 明文
- 缺少 `AUTH_WRAP_KEY_BASE64` 或 `one_way_key` 时无法解密历史记录
