// Discovery over ordinary Nostr relays. No server of ours: any relay that stores kind 10011 works, and every
// event a relay returns is verified locally (a relay can hide data, but it cannot forge a binding).
import type { Event, Filter } from 'nostr-tools';
import { verifyEventFresh } from './verify-event.ts';
import { IDENTITY_KIND, identityName, verifyClaims, type ClaimResult } from './claim.ts';
import type { Network } from './bchmsg.ts';

export const DEFAULT_RELAYS = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net', 'wss://relay.nostr.band'];

/** All events matching `filter` from the given relays (deduplicated, signature-checked). */
export const MAX_EVENTS_PER_RELAY = 200;

export async function query(relays: string[], filter: Filter, timeoutMs = 6000): Promise<Event[]> {
  const byId = new Map<string, Event>();
  await Promise.all(relays.map((url) => new Promise<void>((resolve) => {
    let ws: WebSocket;
    let finished = false;
    const done = () => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      try { ws.close(); } catch { /* */ }
      resolve();
    };
    const timer = setTimeout(done, timeoutMs);
    try { ws = new WebSocket(url); } catch { done(); return; }
    const sub = `tk${Math.random().toString(36).slice(2, 8)}`;
    let count = 0;
    ws.onopen = () => ws.send(JSON.stringify(['REQ', sub, filter]));
    ws.onmessage = (m) => {
      try {
        const d = JSON.parse(String(m.data));
        if (finished) return;
        if (d[0] === 'EVENT' && d[1] === sub && d[2] && !byId.has(d[2].id)) {
          if (++count > MAX_EVENTS_PER_RELAY) { done(); return; } // a relay flooding us is cut off
          if (matchesFilter(filter, d[2]) && verifyEventFresh(d[2])) byId.set(d[2].id, d[2]);
        }
        if ((d[0] === 'EOSE' || d[0] === 'CLOSED') && d[1] === sub) done();
      } catch { /* ignore junk from a relay */ }
    };
    ws.onerror = () => done();
    ws.onclose = () => done();
  })));
  return [...byId.values()];
}

/** Relays are untrusted: keep only events that really match what we asked for. */
export function matchesFilter(f: Filter, e: Event): boolean {
  if (!e || typeof e !== 'object' || !Array.isArray(e.tags)) return false;
  if (f.kinds && !f.kinds.includes(e.kind)) return false;
  if (f.authors && !f.authors.includes(e.pubkey)) return false;
  for (const [k, v] of Object.entries(f)) {
    if (k.startsWith('#') && Array.isArray(v) && !e.tags.some((t) => t[0] === k.slice(1) && (v as string[]).includes(t[1]))) return false;
  }
  return true;
}

const newest = (events: Event[]) => events.slice().sort((a, b) => b.created_at - a.created_at || (a.id < b.id ? -1 : 1))[0];

/** The newest identity list of a pubkey (replaceable event: newest wins, ties broken by lowest id per NIP-01). */
export async function fetchIdentityList(pubkey: string, relays = DEFAULT_RELAYS, timeoutMs?: number): Promise<Event | undefined> {
  return newest((await query(relays, { kinds: [IDENTITY_KIND], authors: [pubkey] }, timeoutMs)).filter((e) => e.pubkey === pubkey && e.kind === IDENTITY_KIND));
}

/** Look up a Nostr identity and verify its BCH claims. */
export async function discoverByPubkey(pubkey: string, network: Network = 'mainnet', relays = DEFAULT_RELAYS, timeoutMs?: number) {
  const list = await fetchIdentityList(pubkey, relays, timeoutMs);
  return { list, results: list ? verifyClaims(list, network) : [] };
}

/**
 * Reverse lookup: which Nostr keys claim this BCH address? Relays index single-letter tags, so `#i` finds
 * candidates; then each author's NEWEST list is fetched, because a user unlinks by publishing a list without
 * the claim, and an older copy that still has it must not count.
 */
export async function discoverByAddress(address: string, network: Network = 'mainnet', relays = DEFAULT_RELAYS, timeoutMs?: number): Promise<ClaimResult[]> {
  const name = identityName(address, network);
  if (!name) throw new Error('Not a P2PKH Bitcoin Cash address');
  const hits = await query(relays, { kinds: [IDENTITY_KIND], '#i': [name] }, timeoutMs);
  // Spam-resistant: only authors whose hit already holds a VALID claim for this address go on. Anyone can publish
  // junk tags naming an address, but nobody can forge the BCH signature, so junk cannot crowd out a real link.
  const authors = [...new Set(hits.filter((e) => verifyClaims(e, network).some((r) => r.ok && r.address && identityName(r.address, network) === name)).map((e) => e.pubkey))].slice(0, 50);
  if (!authors.length) return [];
  const lists = await query(relays, { kinds: [IDENTITY_KIND], authors }, timeoutMs);
  const out: ClaimResult[] = [];
  for (const a of authors) {
    const latest = newest([...lists, ...hits].filter((e) => e.pubkey === a && e.kind === IDENTITY_KIND));
    if (!latest) continue;
    const want = identityName(address, network);
    out.push(...verifyClaims(latest, network).filter((r) => r.address && identityName(r.address, network) === want));
  }
  return out;
}

export type Publisher = (event: Event, relays: string[]) => Promise<{ accepted: string[]; errors: string[] }>;

/** Send an event to every relay; reports which accepted it. */
export const publish: Publisher = async (event, relays) => {
  const accepted: string[] = [];
  const errors: string[] = [];
  await Promise.all(relays.map((url) => new Promise<void>((resolve) => {
    let ws: WebSocket;
    let finished = false;
    const done = (err?: string) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      if (err) errors.push(`${url}: ${err}`);
      try { ws.close(); } catch { /* */ }
      resolve();
    };
    const timer = setTimeout(() => done('timeout'), 8000);
    try { ws = new WebSocket(url); } catch (e) { done(String(e)); return; }
    ws.onopen = () => ws.send(JSON.stringify(['EVENT', event]));
    ws.onmessage = (m) => {
      try {
        const d = JSON.parse(String(m.data));
        if (d[0] === 'OK' && d[1] === event.id) {
          if (d[2] === true || /duplicate/i.test(String(d[3] ?? ''))) { accepted.push(url); done(); } else done(String(d[3] ?? 'rejected'));
        }
      } catch { /* */ }
    };
    ws.onerror = () => done('connection failed');
  })));
  return { accepted, errors };
};
