// Server-side login with TwinKey: the same checks as the demo app, in plain Node (no framework).
//   npm run auth-server                       (listens on http://127.0.0.1:8788)
//   GET  /challenge  → { url, method, nonce, expiresAt }
//   POST <that url>  with header  Authorization: Nostr base64(<signed kind 27235 event>)
//        optional header  X-BCH-Signature: <signature of bchLoginText(challenge, pubkey)>
//   → 200 { npub, bch: [addresses], bothKeys } or 401 { checks }
import { createServer } from 'node:http';
import { nip19 } from 'nostr-tools';
import { newChallenge, parseAuthHeader, verifyAuth, verifyBchStepUp, type Challenge } from '../src/lib/auth.ts';
import { DEFAULT_RELAYS, discoverByPubkey } from '../src/lib/relays.ts';

const PORT = Number(process.env.PORT ?? 8788);
const RELAYS = process.env.RELAYS ? process.env.RELAYS.split(',') : DEFAULT_RELAYS;
const BASE = process.env.BASE_URL ?? `http://127.0.0.1:${PORT}`;
const MAX_PENDING = 10_000;
const pending = new Map<string, Challenge>(); // nonce → challenge
const used = new Map<string, number>(); // nonce → expiry; kept until the challenge could no longer be valid anyway
const usedSet = { has: (n: string) => used.has(n), add: (n: string) => { used.set(n, (pending.get(n)?.expiresAt ?? 0) + 60); return usedSet; } } as unknown as Set<string>;
setInterval(() => {
  const now = Date.now() / 1000;
  for (const [n, c] of pending) if (c.expiresAt < now) pending.delete(n);
  for (const [n, exp] of used) if (exp < now) used.delete(n);
}, 30_000).unref();

const json = (res: import('node:http').ServerResponse, code: number, body: unknown) => {
  res.writeHead(code, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body, null, 2));
};

createServer(async (req, res) => {
  try { await handle(req, res); } catch { if (!res.headersSent) json(res, 400, { error: 'bad request' }); }
}).listen(PORT, '127.0.0.1', () => console.log(`TwinKey auth example on ${BASE} (relays: ${RELAYS.join(', ')})`));

async function handle(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) {
  const url = new URL(req.url ?? '/', BASE);
  if (req.method === 'GET' && url.pathname === '/challenge') {
    if (pending.size >= MAX_PENDING) pending.delete(pending.keys().next().value!); // evict the oldest (a real server would also rate-limit per IP)
    const c = newChallenge(`${BASE}/login`);
    pending.set(c.nonce, c);
    return json(res, 200, c);
  }
  if (req.method === 'POST' && url.pathname === '/login') {
    const c = pending.get(url.searchParams.get('nonce') ?? '');
    const event = parseAuthHeader(req.headers.authorization);
    if (!c || !event) return json(res, 401, { error: 'unknown challenge or missing Authorization: Nostr header' });
    const auth = verifyAuth(event, c, { used: usedSet });
    pending.delete(c.nonce); // one attempt per challenge, whatever the outcome
    if (!auth.ok) return json(res, 401, { checks: auth.checks });
    const { results } = await discoverByPubkey(auth.pubkey!, 'mainnet', RELAYS);
    const links = results.filter((r) => r.ok);
    if (!links.length) return json(res, 401, { checks: auth.checks, error: 'no valid BCH link on the relays' });
    const bchSig = req.headers['x-bch-signature'];
    const signedBy = typeof bchSig === 'string' ? links.find((l) => verifyBchStepUp(c, auth.pubkey!, l.address!, bchSig).ok)?.address : undefined;
    return json(res, 200, { npub: nip19.npubEncode(auth.pubkey!), bch: links.map((l) => l.address), bothKeys: !!signedBy, bchSignedBy: signedBy ?? null });
  }
  json(res, 404, { error: 'not found' });
}
