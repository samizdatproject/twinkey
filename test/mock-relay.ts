// A tiny in-memory Nostr relay (NIP-01 subset) for tests and local demos: EVENT with replaceable-event
// semantics, REQ with ids/kinds/authors/#<letter>/since/until/limit, EOSE, OK, CLOSE.
import { WebSocketServer, type WebSocket } from 'ws';
import { verifyEvent, type Event, type Filter } from 'nostr-tools';

const replaceable = (k: number) => k === 0 || k === 3 || (k >= 10000 && k < 20000);
const ephemeral = (k: number) => k >= 20000 && k < 30000;

export function matches(f: Filter, e: Event): boolean {
  if (f.ids && !f.ids.includes(e.id)) return false;
  if (f.kinds && !f.kinds.includes(e.kind)) return false;
  if (f.authors && !f.authors.includes(e.pubkey)) return false;
  if (f.since && e.created_at < f.since) return false;
  if (f.until && e.created_at > f.until) return false;
  for (const [k, v] of Object.entries(f)) {
    if (k.startsWith('#') && Array.isArray(v)) {
      const letter = k.slice(1);
      if (!e.tags.some((t) => t[0] === letter && (v as string[]).includes(t[1]))) return false;
    }
  }
  return true;
}

export async function startMockRelay(port = 0) {
  const events: Event[] = [];
  const wss = new WebSocketServer({ port, host: '127.0.0.1' });
  await new Promise<void>((r) => wss.once('listening', () => r()));
  const subs = new Map<WebSocket, Map<string, Filter[]>>();
  wss.on('connection', (ws) => {
    subs.set(ws, new Map());
    ws.on('message', (raw) => {
      let msg: any;
      try { msg = JSON.parse(String(raw)); } catch { return; }
      if (msg[0] === 'EVENT') {
        const e: Event = msg[1];
        if (!verifyEvent(e)) { ws.send(JSON.stringify(['OK', e?.id, false, 'invalid: bad signature'])); return; }
        if (events.some((x) => x.id === e.id)) { ws.send(JSON.stringify(['OK', e.id, true, 'duplicate: have it'])); return; }
        if (replaceable(e.kind)) {
          const old = events.find((x) => x.kind === e.kind && x.pubkey === e.pubkey);
          if (old && (old.created_at > e.created_at || (old.created_at === e.created_at && old.id < e.id))) {
            ws.send(JSON.stringify(['OK', e.id, false, 'duplicate: have a newer one'])); return;
          }
          if (old) events.splice(events.indexOf(old), 1);
        }
        if (!ephemeral(e.kind)) events.push(e);
        ws.send(JSON.stringify(['OK', e.id, true, '']));
        for (const [client, s] of subs) for (const [id, fs] of s) if (fs.some((f) => matches(f, e))) client.send(JSON.stringify(['EVENT', id, e]));
      } else if (msg[0] === 'REQ') {
        const [, id, ...filters] = msg as [string, string, ...Filter[]];
        subs.get(ws)!.set(id, filters);
        const out = new Map<string, Event>();
        for (const f of filters) {
          const hit = events.filter((e) => matches(f, e)).sort((a, b) => b.created_at - a.created_at);
          for (const e of hit.slice(0, f.limit ?? hit.length)) out.set(e.id, e);
        }
        for (const e of out.values()) ws.send(JSON.stringify(['EVENT', id, e]));
        ws.send(JSON.stringify(['EOSE', id]));
      } else if (msg[0] === 'CLOSE') {
        subs.get(ws)!.delete(msg[1]);
      }
    });
    ws.on('close', () => subs.delete(ws));
  });
  const { port: p } = wss.address() as { port: number };
  return {
    url: `ws://127.0.0.1:${p}`,
    events,
    /** Put an event in the store directly (e.g. an old copy a relay kept). */
    inject: (e: Event) => events.push(e),
    close: () => new Promise<void>((r) => { for (const c of wss.clients) c.terminate(); wss.close(() => r()); }),
  };
}
