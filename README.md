# Codex auth relay

This Next.js app implements the relay and encrypted auth upload endpoints from
`NEXTJS_AUTH_RELAY_INTEGRATION.md`.

## Environment

```bash
AUTH_WRAP_KEY_BASE64="32-byte-random-value-base64"
HANDSHAKE_TTL_SECONDS="120"
REDIS_URL="redis://localhost:6379"
```

Redis is used for short-lived handshakes and wrapped `auth.json` records. Stored
auth records are keyed by the SHA-256 fingerprint of a server-generated relay
key: `codex-relay:auth:<fingerprint>`. The relay key itself is not written to
Redis. Stored auth encryption is derived from both `AUTH_WRAP_KEY_BASE64` and an
additional `one_way_key`, so neither the database record nor the browser-returned
keys can decrypt `auth.json` without this server environment. The relay key is
returned once after a successful upload as the `api_key` inside
`relay_server_key.json` content, and `one_way_key` is added alongside it for the
extra auth wrapper.

## Getting Started

First, run the development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

You can start editing the page by modifying `app/page.tsx`. The page auto-updates as you edit the file.

This project uses [`next/font`](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) to automatically optimize and load [Geist](https://vercel.com/font), a new font family for Vercel.

## Learn More

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

You can check out [the Next.js GitHub repository](https://github.com/vercel/next.js) - your feedback and contributions are welcome!

## Deploy on Vercel

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.
