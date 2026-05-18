import { NextRequest, NextResponse } from "next/server";
import {
  generateServerKeyPair,
  isBase64UrlString,
  isP256PublicJwk,
  randomBase64Url,
  type HandshakeRecord,
} from "@/lib/auth-crypto";
import { handshakeRedisKey } from "@/lib/auth-storage";
import { getPresentedRelayKey } from "@/lib/relay-auth";
import { getRedis } from "@/lib/redis";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function jsonError(error: string, status: number) {
  return NextResponse.json({ error }, { status });
}

function handshakeTtlSeconds() {
  const parsed = Number.parseInt(process.env.HANDSHAKE_TTL_SECONDS || "120", 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 120;
}

export async function POST(req: NextRequest) {
  const relayKey = getPresentedRelayKey(req);
  if (!relayKey) {
    return jsonError("unauthorized", 401);
  }

  let input: {
    clientPublicJwk?: unknown;
    clientNonce?: unknown;
  };

  try {
    input = (await req.json()) as typeof input;
  } catch {
    return jsonError("invalid_json", 400);
  }

  if (!isP256PublicJwk(input.clientPublicJwk)) {
    return jsonError("invalid_client_public_jwk", 400);
  }

  if (!isBase64UrlString(input.clientNonce)) {
    return jsonError("invalid_client_nonce", 400);
  }

  const ttl = handshakeTtlSeconds();
  const handshakeId = randomBase64Url(18);
  const serverNonce = randomBase64Url(32);
  const expiresAt = new Date(Date.now() + ttl * 1000).toISOString();
  const { publicJwk, privateJwk } = await generateServerKeyPair();
  const record: HandshakeRecord = {
    handshakeId,
    relayKeyId: relayKey.id,
    serverPrivateJwk: privateJwk,
    clientPublicJwk: input.clientPublicJwk,
    clientNonce: input.clientNonce,
    serverNonce,
    expiresAt,
    used: false,
  };

  const redis = await getRedis();
  await redis.set(handshakeRedisKey(handshakeId), JSON.stringify(record), {
    expiration: { type: "EX", value: ttl },
  });

  return NextResponse.json(
    {
      handshakeId,
      serverPublicJwk: publicJwk,
      serverNonce,
      expiresAt,
    },
    { headers: { "cache-control": "no-store" } },
  );
}
