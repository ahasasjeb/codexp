import { NextRequest, NextResponse } from "next/server";
import { authenticateRelayKey } from "@/lib/relay-auth";

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

export async function POST(req: NextRequest) {
  if (!(await authenticateRelayKey(req))) {
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

  const upstream = await fetch(target.toString(), {
    method,
    headers: parseHeaderLines(input.headers || ""),
    body: method === "GET" || method === "HEAD" ? undefined : input.body || "",
    cache: "no-store",
  });

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
