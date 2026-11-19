// Shared UI helpers for both pages: keys (browser extension or local demo keys), relays, rendering.
import { finalizeEvent, generateSecretKey, getPublicKey, nip19, type Event, type EventTemplate } from 'nostr-tools';
import { bytesToHex, hexToBytes } from 'nostr-tools/utils';
import { queryProfile } from 'nostr-tools/nip05';
import { generatePrivateKey } from '@bitauth/libauth';
import { addressOf, signMessage } from '../lib/bchmsg.ts';
import { DEFAULT_RELAYS } from '../lib/relays.ts';
import type { Check } from '../lib/claim.ts';
import { toPubkeyHex } from '../lib/claim.ts';

// ---- tiny DOM helper: text is always set with textContent, never parsed as HTML
type Attrs = Record<string, string | boolean | ((e: any) => void)>;
export function el<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Attrs = {}, ...kids: (Node | string | null | undefined | false)[]): HTMLElementTagNameMap[K] {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (typeof v === 'function') n.addEventListener(k.replace(/^on/, ''), v);
    else if (v === true) n.setAttribute(k, '');
    else if (v !== false) n.setAttribute(k, v);
  }
  for (const k of kids) if (k !== null && k !== undefined && k !== false) n.append(typeof k === 'string' ? document.createTextNode(k) : k);
  return n;
}
export const $ = <T extends HTMLElement = HTMLElement>(sel: string) => document.querySelector(sel) as T;
export const short = (s: string, n = 10) => (s.length > 2 * n + 1 ? `${s.slice(0, n)}…${s.slice(-n)}` : s);

export function renderChecks(checks: Check[]): HTMLElement {
  return el('ul', { class: 'checks' }, ...checks.map((c) => el('li', { class: c.ok ? 'ok' : 'bad' },
    el('span', { class: 'mark' }, c.ok ? '✓' : '✗'), ` ${c.name}`, c.detail ? el('small', {}, ` — ${c.detail}`) : null)));
}

export async function copy(text: string, btn?: HTMLElement) {
  try {
    await navigator.clipboard.writeText(text);
    if (btn) { const t = btn.textContent; btn.textContent = 'Copied'; setTimeout(() => (btn.textContent = t), 1200); }
  } catch { /* clipboard blocked: the text is visible anyway */ }
}

// ---- storage (best effort: private windows may block it)
const store = {
  get: (k: string) => { try { return localStorage.getItem(k); } catch { return null; } },
  set: (k: string, v: string) => { try { localStorage.setItem(k, v); } catch { /* */ } },
  del: (k: string) => { try { localStorage.removeItem(k); } catch { /* */ } },
};

// ---- relays
export function getRelays(): string[] {
  const saved = store.get('twinkey.relays');
  const list = saved ? saved.split(/\s+/).filter((r) => /^wss?:\/\//.test(r)) : [];
  return list.length ? list : DEFAULT_RELAYS;
}
export const setRelays = (text: string) => store.set('twinkey.relays', text.trim());

// ---- Nostr signer: a NIP-07 browser extension, or a demo key kept in this browser
declare global {
  interface Window { nostr?: { getPublicKey(): Promise<string>; signEvent(e: EventTemplate): Promise<Event> } }
}
export interface NostrSigner { kind: 'extension' | 'demo'; pubkey: string; sign(t: EventTemplate): Promise<Event> }

export async function extensionSigner(): Promise<NostrSigner> {
  if (!window.nostr) throw new Error('No Nostr browser extension found (for example Alby or nos2x). Use a demo key instead.');
  const pubkey = await window.nostr.getPublicKey();
  return { kind: 'extension', pubkey, sign: (t) => window.nostr!.signEvent(t) };
}

export function demoNostrSigner(create = true): NostrSigner | undefined {
  let hex = store.get('twinkey.demo.nostr');
  if (!hex && !create) return undefined;
  if (!hex) { hex = bytesToHex(generateSecretKey()); store.set('twinkey.demo.nostr', hex); }
  const sk = hexToBytes(hex);
  return { kind: 'demo', pubkey: getPublicKey(sk), sign: async (t) => finalizeEvent(t, sk) };
}
export const demoNsec = () => { const h = store.get('twinkey.demo.nostr'); return h ? nip19.nsecEncode(hexToBytes(h)) : undefined; };

// ---- BCH demo key (a real mainnet key, kept in this browser; for the demo, never hold funds on it)
export interface BchDemo { address: string; sign(message: string): string }
export function demoBch(create = true): BchDemo | undefined {
  let hex = store.get('twinkey.demo.bch');
  if (!hex && !create) return undefined;
  if (!hex) { hex = bytesToHex(generatePrivateKey()); store.set('twinkey.demo.bch', hex); }
  const key = hexToBytes(hex);
  return { address: addressOf(key), sign: (m) => signMessage(key, m) };
}
export function forgetDemoKeys() { store.del('twinkey.demo.nostr'); store.del('twinkey.demo.bch'); }

/** npub / nprofile / hex / name@domain (NIP-05) → hex pubkey. */
export async function resolvePubkey(input: string): Promise<string | undefined> {
  const s = input.trim();
  const direct = toPubkeyHex(s);
  if (direct) return direct;
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s) || /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(s)) {
    const p = await queryProfile(s).catch(() => null);
    return p?.pubkey;
  }
  return undefined;
}
