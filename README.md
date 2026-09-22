# Key System Worker

Cloudflare Worker combining:
- Pastebin CORS proxy (`GET /?id=...`, `POST /create`)
- Linkvertise Anti-Bypass verification + key issuance (`POST /verify`)

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET  | `/?id=PASTE_ID` | Read raw Pastebin paste |
| POST | `/create`       | Create a new Pastebin paste |
| POST | `/verify`       | Verify Linkvertise hash → issue key |

## Deploy

1. `npm install`
2. `npx wrangler d1 create axom-keys` → paste ID into `wrangler.toml`
3. `npx wrangler d1 execute axom-keys --remote --file=./schema.sql`
4. `npx wrangler secret put PASTEBIN_DEV_KEY`
5. `npx wrangler secret put PASTEBIN_USER_KEY`
6. `npx wrangler secret put LINKVERTISE_ANTI_BYPASS_TOKEN`
7. `npm run deploy`
