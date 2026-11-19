// Logging in to an app with the linked identity. Standard NIP-98 (HTTP Auth, kind 27235): the app issues a
// one-time URL containing a nonce; the user's Nostr key signs an event naming that URL; the app checks the
// signature, the URL, the age and that the nonce is unused, then looks up the BCH claim on relays.
// Optional step-up: the BCH key also signs a one-line login text, proving the user holds BOTH keys right now.
import { nip19, type Event, type EventTemplate } from 'nostr-tools';
import { verifyEventFresh } from './verify-event.ts';
import { bytesToHex } from 'nostr-tools/utils';
import { verifyMessage, type Network } from './bchmsg.ts';
import type { Check } from './claim.ts';

export const AUTH_KIND = 27235;

export interface Challenge { url: string; method: string; nonce: string; expiresAt: number }

export function newChallenge(endpoint: string, ttlSec = 120, now = Date.now(), method = 'POST'): Challenge {
  const nonce = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
  const u = new URL(endpoint);
  u.searchParams.set('nonce', nonce);
  return { url: u.toString(), method, nonce, expiresAt: Math.floor(now / 1000) + ttlSec };
}

export const authTemplate = (c: Pick<Challenge, 'url' | 'method'>, now = Date.now()): EventTemplate => ({
  kind: AUTH_KIND, created_at: Math.floor(now / 1000), content: '', tags: [['u', c.url], ['method', c.method]],
});

/** The one-line text the BCH key signs for the optional step-up. */
export const bchLoginText = (c: Pick<Challenge, 'url' | 'nonce'>, pubkeyHex: string) =>
  `Log in to ${new URL(c.url).origin} as ${nip19.npubEncode(pubkeyHex)} with nonce ${c.nonce}`;

export interface AuthOptions {
  now?: number;
  maxSkewSec?: number; // NIP-98 suggests 60 s
  used: Set<string>; // nonces already accepted (replay protection); the caller keeps it
}

/** Verify a login event against the challenge the app issued. Marks the nonce used only on success. */
export function verifyAuth(event: Event, c: Challenge, opts: AuthOptions): { ok: boolean; pubkey?: string; checks: Check[] } {
  const now = Math.floor((opts.now ?? Date.now()) / 1000);
  const skew = opts.maxSkewSec ?? 60;
  const tag = (n: string) => event.tags.find((t) => t[0] === n)?.[1];
  let sig = false;
  sig = verifyEventFresh(event);
  const checks: Check[] = [
    { name: 'Login event is NIP-98 (kind 27235)', ok: event.kind === AUTH_KIND },
    { name: 'Nostr signature valid', ok: sig },
    { name: 'Signed for this app and this one-time URL', ok: tag('u') === c.url, detail: tag('u') },
    { name: 'Method matches', ok: (tag('method') ?? '').toUpperCase() === c.method.toUpperCase() },
    { name: 'Fresh (signed within 60 s, challenge not expired)', ok: Math.abs(now - event.created_at) <= skew && now <= c.expiresAt },
    { name: 'Nonce not used before (no replay)', ok: !opts.used.has(c.nonce) },
  ];
  const ok = checks.every((x) => x.ok);
  if (ok) opts.used.add(c.nonce);
  return { ok, pubkey: ok ? event.pubkey : undefined, checks };
}

/** Optional step-up: the BCH key signed the login text for this nonce and this Nostr key. */
export function verifyBchStepUp(c: Challenge, pubkeyHex: string, address: string, signature: string, network: Network = 'mainnet'): Check {
  const ok = verifyMessage(address, signature, bchLoginText(c, pubkeyHex), network);
  return { name: 'BCH key signed this login too (holds both keys now)', ok, detail: address };
}

/** The NIP-98 Authorization header value for an HTTP request. */
export const authHeader = (event: Event) => `Nostr ${btoa(JSON.stringify(event))}`;
export function parseAuthHeader(value: string | undefined): Event | undefined {
  const m = /^Nostr\s+(.+)$/.exec(value ?? '');
  if (!m) return undefined;
  try { return JSON.parse(atob(m[1])) as Event; } catch { return undefined; }
}
