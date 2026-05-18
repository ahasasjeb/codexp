type CodexAuthJson = {
  auth_mode?: unknown;
  tokens?: {
    access_token?: unknown;
  };
  access_token?: unknown;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function validateCodexAuthJson(value: unknown) {
  if (!isRecord(value)) {
    return false;
  }

  const auth = value as CodexAuthJson;
  const nestedAccessToken = auth.tokens?.access_token;
  const accessToken =
    typeof auth.access_token === "string"
      ? auth.access_token
      : nestedAccessToken;

  return (
    auth.auth_mode === "chatgpt" &&
    typeof accessToken === "string" &&
    accessToken.length > 0
  );
}
