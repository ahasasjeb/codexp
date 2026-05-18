import { NextRequest, NextResponse } from "next/server";
import { authenticateRelayKey } from "@/lib/relay-auth";
import { deleteWrappedAuth, recordUsageFailure } from "@/lib/auth-storage";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const allowedHosts = new Set(["chatgpt.com", "auth.openai.com"]);
const allowedMethods = new Set([
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
  "OPTIONS",
]);
const usageFailureStatus = 498;
const usageFailureLimit = 2;

function jsonError(error: string, status: number) {
  return NextResponse.json({ error }, { status });
}

function parseHeaderLines(raw: string) {
  const headers = new Headers();
  for (const line of raw.split(/\r?\n/)) {
    const idx = line.indexOf(":");
    if (idx <= 0) {
      continue;
    }

    const name = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (!name || /^(host|content-length|connection)$/i.test(name)) {
      continue;
    }
    headers.set(name, value);
  }
  return headers;
}

function isUsageRequest(target: URL) {
  return (
    target.hostname === "chatgpt.com" &&
    target.pathname === "/backend-api/wham/usage"
  );
}

async function countUsageFailure(id: string) {
  const count = await recordUsageFailure(id);
  if (count >= usageFailureLimit) {
    await deleteWrappedAuth(id);
    return true;
  }
  return false;
}

export async function POST(req: NextRequest) {
  const authenticated = await authenticateRelayKey(req);
  if (!authenticated) {
    return jsonError("unauthorized", 401);
  }

  let input: {
    method?: string;
    url?: string;
    headers?: string;
    body?: string;
  };

  try {
    input = (await req.json()) as typeof input;
  } catch {
    return jsonError("invalid_json", 400);
  }

  const method = (input.method || "GET").toUpperCase();
  if (!allowedMethods.has(method)) {
    return jsonError("method_not_allowed", 400);
  }

  let target: URL;
  try {
    target = new URL(input.url || "");
  } catch {
    return jsonError("invalid_url", 400);
  }

  if (target.protocol !== "https:" || !allowedHosts.has(target.hostname)) {
    return jsonError("target_not_allowed", 400);
  }

  let upstream: Response;
  try {
    upstream = await fetch(target.toString(), {
      method,
      headers: parseHeaderLines(input.headers || ""),
      body: method === "GET" || method === "HEAD" ? undefined : input.body || "",
      cache: "no-store",
    });
  } catch {
    if (isUsageRequest(target) && (await countUsageFailure(authenticated.id))) {
      return jsonError("usage_auth_removed", usageFailureStatus);
    }
    return jsonError("upstream_fetch_failed", 502);
  }

  if (
    isUsageRequest(target) &&
    !upstream.ok &&
    (await countUsageFailure(authenticated.id))
  ) {
    return jsonError("usage_auth_removed", usageFailureStatus);
  }

  return new NextResponse(await upstream.text(), {
    status: upstream.status,
    headers: {
      "content-type":
        upstream.headers.get("content-type") ||
        "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}
