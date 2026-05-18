import crypto from "node:crypto";

const textEncoder = new TextEncoder();
const uploadInfo = Buffer.from("codex-auth-upload-v1");
const storageInfo = Buffer.from("codex-auth-json-storage-v2");
const storageAad = Buffer.from("codex-auth-json-storage-v2");

export type HandshakeRecord = {
  handshakeId: string;
  serverPrivateJwk: JsonWebKey;
  clientPublicJwk: JsonWebKey;
  clientNonce: string;
  serverNonce: string;
  expiresAt: string;
  used: boolean;
};

export type StoredAuth = {
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

export function randomBase64Url(size: number) {
  return crypto.randomBytes(size).toString("base64url");
}

export function isBase64UrlString(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    /^[A-Za-z0-9_-]+$/.test(value)
  );
}

export function decodeBase64Url(value: string) {
  if (!isBase64UrlString(value)) {
    throw new Error("invalid_base64url");
  }
  return Buffer.from(value, "base64url");
}

export function isP256PublicJwk(value: unknown): value is JsonWebKey {
  if (!value || typeof value !== "object") {
    return false;
  }

  const jwk = value as JsonWebKey;
  return (
    jwk.kty === "EC" &&
    jwk.crv === "P-256" &&
    typeof jwk.x === "string" &&
    typeof jwk.y === "string"
  );
}

export async function generateServerKeyPair() {
  const keyPair = await crypto.webcrypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );

  const [publicJwk, privateJwk] = await Promise.all([
    crypto.webcrypto.subtle.exportKey("jwk", keyPair.publicKey),
    crypto.webcrypto.subtle.exportKey("jwk", keyPair.privateKey),
  ]);

  return { publicJwk, privateJwk };
}

function deriveUploadKey(
  sharedSecret: Buffer,
  clientNonce: string,
  serverNonce: string,
) {
  const salt = Buffer.concat([
    decodeBase64Url(clientNonce),
    decodeBase64Url(serverNonce),
  ]);
  return Buffer.from(
    crypto.hkdfSync("sha256", sharedSecret, salt, uploadInfo, 32),
  );
}

export async function decryptUploadedAuth(
  record: HandshakeRecord,
  iv: string,
  ciphertext: string,
) {
  const serverPrivateKey = await crypto.webcrypto.subtle.importKey(
    "jwk",
    record.serverPrivateJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  const clientPublicKey = await crypto.webcrypto.subtle.importKey(
    "jwk",
    record.clientPublicJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const sharedSecretBits = await crypto.webcrypto.subtle.deriveBits(
    { name: "ECDH", public: clientPublicKey },
    serverPrivateKey,
    256,
  );
  const keyBytes = deriveUploadKey(
    Buffer.from(sharedSecretBits),
    record.clientNonce,
    record.serverNonce,
  );
  const aesKey = await crypto.webcrypto.subtle.importKey(
    "raw",
    keyBytes,
    "AES-GCM",
    false,
    ["decrypt"],
  );

  const plainText = await crypto.webcrypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: decodeBase64Url(iv),
      additionalData: textEncoder.encode(
        `${record.handshakeId}.${record.clientNonce}.${record.serverNonce}`,
      ),
    },
    aesKey,
    decodeBase64Url(ciphertext),
  );

  return Buffer.from(plainText).toString("utf8");
}

function wrapKey() {
  const key = Buffer.from(process.env.AUTH_WRAP_KEY_BASE64 || "", "base64");
  if (key.length !== 32) {
    throw new Error("invalid AUTH_WRAP_KEY_BASE64");
  }
  return key;
}

function deriveStorageKey(oneWayKey: string) {
  const salt = crypto.createHash("sha256").update(oneWayKey, "utf8").digest();
  return Buffer.from(crypto.hkdfSync("sha256", wrapKey(), salt, storageInfo, 32));
}

export function encryptForStorage(plainText: string, oneWayKey: string) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    deriveStorageKey(oneWayKey),
    iv,
  );
  cipher.setAAD(storageAad);
  const ciphertext = Buffer.concat([
    cipher.update(plainText, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return {
    algorithm: "AES-256-GCM" as const,
    key_id: "env:AUTH_WRAP_KEY_BASE64+one_way_key:v2" as const,
    iv: iv.toString("base64url"),
    tag: tag.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
  };
}

export function decryptFromStorage(
  record: {
    iv: string;
    tag: string;
    ciphertext: string;
  },
  oneWayKey: string,
) {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    deriveStorageKey(oneWayKey),
    Buffer.from(record.iv, "base64url"),
  );
  decipher.setAAD(storageAad);
  decipher.setAuthTag(Buffer.from(record.tag, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(record.ciphertext, "base64url")),
    decipher.final(),
  ]).toString("utf8");
}
