# Hooklab

Internal webhook demo harness for purchase invoice event verification.

## Project Structure

- `src/server.ts` — Elysia dashboard + webhook receiver + trigger APIs
- `src/lib/webhook-utils.ts` — config parsing and HMAC verification helpers
- `tests/webhook-demo.test.ts` — unit tests for parsing and signature verification

## Commands

- `bun run dev` — start local dashboard (`http://localhost:9876`)
- `bun run start` — start server
- `bun run test` — run tests
