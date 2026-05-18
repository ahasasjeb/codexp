import { encryptForStorage, type StoredAuth } from "./auth-crypto";
import { getRedis } from "./redis";

const AUTH_INDEX_KEY = "codex-relay:auth:index";
const USAGE_FAILURE_TTL_SECONDS = 24 * 60 * 60;

export function storedAuthRedisKey(id: string) {
  return `codex-relay:auth:${id}`;
}

export function usageFailureRedisKey(id: string) {
  return `codex-relay:auth:${id}:usage-failures`;
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

export async function saveWrappedAuth(
  id: string,
  plainText: string,
  oneWayKey: string,
) {
  const redis = await getRedis();
  const now = new Date().toISOString();
  const key = storedAuthRedisKey(id);
  const existing = await redis.get(key);
  const encrypted = encryptForStorage(plainText, oneWayKey);
  const record: StoredAuth = {
    id,
    version: 2,
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

export async function recordUsageFailure(id: string) {
  const redis = await getRedis();
  const key = usageFailureRedisKey(id);
  const count = await redis.incr(key);
  if (count === 1) {
    await redis.expire(key, USAGE_FAILURE_TTL_SECONDS);
  }
  return count;
}

export async function deleteWrappedAuth(id: string) {
  const redis = await getRedis();
  await redis
    .multi()
    .del(storedAuthRedisKey(id))
    .sRem(AUTH_INDEX_KEY, id)
    .del(usageFailureRedisKey(id))
    .exec();
}
