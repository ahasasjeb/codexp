import crypto from "node:crypto";
import type { NextRequest } from "next/server";
import { getRedis } from "./redis";

export const RELAY_KEY_SET = "codex-relay:api-keys";

export type AuthenticatedRelayKey = {
  id: string;
};

function configuredRelayKeys() {
  return (process.env.CODEX_RELAY_API_KEY || "")
    .split(/[\s,]+/)
    .map((key) => key.trim())
    .filter(Boolean);
}

function extractCandidateKeys(req: NextRequest) {
  const keys: string[] = [];
  const authorization = req.headers.get("authorization") || "";
  const bearerMatch = authorization.match(/^Bearer\s+(.+)$/i);
  if (bearerMatch?.[1]) {
    keys.push(bearerMatch[1].trim());
  }

  const headerKey = req.headers.get("x-codex-relay-key");
  if (headerKey) {
    keys.push(headerKey.trim());
  }

  return Array.from(new Set(keys.filter(Boolean)));
}

export function relayKeyId(key: string) {
  return crypto.createHash("sha256").update(key, "utf8").digest("hex");
}

function timingSafeEqualString(left: string, right: string) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return (
    leftBuffer.length === rightBuffer.length &&
    crypto.timingSafeEqual(leftBuffer, rightBuffer)
  );
}

async function isRedisRelayKey(id: string) {
  if (!process.env.REDIS_URL) {
    return false;
  }

  const redis = await getRedis();
  return redis.sIsMember(RELAY_KEY_SET, id);
}

export async function authenticateRelayKey(
  req: NextRequest,
): Promise<AuthenticatedRelayKey | null> {
  const candidates = extractCandidateKeys(req);
  if (candidates.length === 0) {
    return null;
  }

  const envKeyIds = configuredRelayKeys().map(relayKeyId);
  for (const candidate of candidates) {
    const id = relayKeyId(candidate);
    if (envKeyIds.some((expectedId) => timingSafeEqualString(id, expectedId))) {
      return { id };
    }

    if (await isRedisRelayKey(id)) {
      return { id };
    }
  }

  return null;
}
