import { NextRequest, NextResponse } from "next/server";
import {
  decryptUploadedAuth,
  isBase64UrlString,
  randomBase64Url,
  type HandshakeRecord,
} from "@/lib/auth-crypto";
import { validateCodexAuthJson } from "@/lib/auth-json";
import { handshakeRedisKey, saveWrappedAuth } from "@/lib/auth-storage";
import { relayKeyId } from "@/lib/relay-auth";
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

  const relayKey = `cr_${randomBase64Url(32)}`;
  const oneWayKey = `ow_${randomBase64Url(32)}`;
  const stored = await saveWrappedAuth(
    relayKeyId(relayKey),
    plainText,
    oneWayKey,
  );
  return NextResponse.json(
    {
      ok: true,
      id: stored.id,
      relay_api_key: relayKey,
      one_way_key: oneWayKey,
      server_url: new URL("/api/codex-relay", req.nextUrl.origin).toString(),
      updated_at: stored.updated_at,
    },
    { headers: { "cache-control": "no-store" } },
  );
}
