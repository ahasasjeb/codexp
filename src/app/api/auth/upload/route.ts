import { NextRequest, NextResponse } from "next/server";
import {
  decryptUploadedAuth,
  isBase64UrlString,
  type HandshakeRecord,
} from "@/lib/auth-crypto";
import { validateCodexAuthJson } from "@/lib/auth-json";
import { handshakeRedisKey, saveWrappedAuth } from "@/lib/auth-storage";
import { getPresentedRelayKey } from "@/lib/relay-auth";
import { getRedis } from "@/lib/redis";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function jsonError(error: string, status: number) {
  return NextResponse.json({ error }, { status });
}

function isExpired(record: HandshakeRecord) {
  return Date.parse(record.expiresAt) <= Date.now();
}

function parseHandshakeRecord(raw: string) {
  return JSON.parse(raw) as HandshakeRecord;
}

export async function POST(req: NextRequest) {
  const relayKey = getPresentedRelayKey(req);
  if (!relayKey) {
    return jsonError("unauthorized", 401);
  }

  let input: {
    handshakeId?: unknown;
    clientNonce?: unknown;
    serverNonce?: unknown;
    iv?: unknown;
    ciphertext?: unknown;
  };

  try {
    input = (await req.json()) as typeof input;
  } catch {
    return jsonError("invalid_json", 400);
  }

  if (
    !isBase64UrlString(input.handshakeId) ||
    !isBase64UrlString(input.clientNonce) ||
    !isBase64UrlString(input.serverNonce) ||
    !isBase64UrlString(input.iv) ||
    !isBase64UrlString(input.ciphertext)
  ) {
    return jsonError("invalid_upload", 400);
  }

  const redis = await getRedis();
  const rawRecord = await redis.getDel(handshakeRedisKey(input.handshakeId));
  if (!rawRecord) {
    return jsonError("handshake_not_found", 400);
  }

  let record: HandshakeRecord;
  try {
    record = parseHandshakeRecord(rawRecord);
  } catch {
    return jsonError("invalid_handshake", 400);
  }

  if (
    record.used ||
    isExpired(record) ||
    record.relayKeyId !== relayKey.id ||
    record.clientNonce !== input.clientNonce ||
    record.serverNonce !== input.serverNonce
  ) {
    return jsonError("invalid_handshake", 400);
  }

  let plainText: string;
  try {
    plainText = await decryptUploadedAuth(
      record,
      input.iv,
      input.ciphertext,
    );
  } catch {
    return jsonError("decrypt_failed", 400);
  }

  let authJson: unknown;
  try {
    authJson = JSON.parse(plainText) as unknown;
  } catch {
    return jsonError("invalid_auth_json", 400);
  }

  if (!validateCodexAuthJson(authJson)) {
    return jsonError("invalid_auth_json", 400);
  }

  const stored = await saveWrappedAuth(relayKey.id, plainText);
  return NextResponse.json(
    {
      ok: true,
      id: stored.id,
      updated_at: stored.updated_at,
    },
    { headers: { "cache-control": "no-store" } },
  );
}
