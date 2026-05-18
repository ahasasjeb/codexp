import crypto from "node:crypto";
import type { NextRequest } from "next/server";
import { storedAuthRedisKey } from "./auth-storage";
import { getRedis } from "./redis";

export type AuthenticatedRelayKey = {
  id: string;
};

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

async function isRedisRelayKey(id: string) {
  if (!process.env.REDIS_URL) {
    return false;
  }

  const redis = await getRedis();
  return (await redis.exists(storedAuthRedisKey(id))) > 0;
}

export async function authenticateRelayKey(
  req: NextRequest,
): Promise<AuthenticatedRelayKey | null> {
  const candidates = extractCandidateKeys(req);
  if (candidates.length === 0) {
    return null;
  }

  for (const candidate of candidates) {
    const id = relayKeyId(candidate);
    if (await isRedisRelayKey(id)) {
      return { id };
    }
  }

  return null;
}
