import { encryptForStorage, type StoredAuth } from "./auth-crypto";
import { getRedis } from "./redis";

const AUTH_INDEX_KEY = "codex-relay:auth:index";

export function storedAuthRedisKey(id: string) {
  return `codex-relay:auth:${id}`;
}

export function handshakeRedisKey(handshakeId: string) {
  return `codex-relay:handshake:${handshakeId}`;
}

function readCreatedAt(raw: string | null, fallback: string) {
  if (!raw) {
    return fallback;
  }

  try {
    const parsed = JSON.parse(raw) as Partial<StoredAuth>;
    return typeof parsed.created_at === "string" ? parsed.created_at : fallback;
  } catch {
    return fallback;
  }
}

export async function saveWrappedAuth(id: string, plainText: string) {
  const redis = await getRedis();
  const now = new Date().toISOString();
  const key = storedAuthRedisKey(id);
  const existing = await redis.get(key);
  const encrypted = encryptForStorage(plainText);
  const record: StoredAuth = {
    id,
    version: 1,
    algorithm: encrypted.algorithm,
    key_id: encrypted.key_id,
    iv: encrypted.iv,
    tag: encrypted.tag,
    ciphertext: encrypted.ciphertext,
    created_at: readCreatedAt(existing, now),
    updated_at: now,
  };

  await redis.set(key, JSON.stringify(record));
  await redis.sAdd(AUTH_INDEX_KEY, id);

  return record;
}
