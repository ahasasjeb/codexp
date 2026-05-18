import { createClient } from "redis";

type CodexRedisClient = ReturnType<typeof createClient>;

declare global {
  var codexRedisClient: CodexRedisClient | undefined;
  var codexRedisConnect: Promise<CodexRedisClient> | undefined;
}

export async function getRedis() {
  const url = process.env.REDIS_URL;
  if (!url) {
    throw new Error("REDIS_URL is required");
  }

  if (!globalThis.codexRedisClient) {
    const client = createClient({ url });
    client.on("error", (error) => {
      const message = error instanceof Error ? error.message : "unknown error";
      console.error(`Redis client error: ${message}`);
    });
    globalThis.codexRedisClient = client;
  }

  const client = globalThis.codexRedisClient;
  if (!client.isOpen) {
    globalThis.codexRedisConnect ??= client.connect().then(() => client);
    try {
      await globalThis.codexRedisConnect;
    } finally {
      globalThis.codexRedisConnect = undefined;
    }
  }

  return client;
}
