// The binding itself: a NIP-39 identity claim of type `bch` inside the user's kind 10011 list.
//
//   ["i", "bch:<cashaddr without prefix>", "<base64 Bitcoin Signed Message signature>"]
//
// The BCH key signs NIP-39's own verification text, which names the Nostr key:
//   "Verifying that I control the following Nostr public key: <npub>"
// and the Nostr key signs the event that carries the address and that signature. So each key vouches for the
// other, neither key is revealed, and the two keys are different (one secp256k1 ECDSA, one BIP-340 Schnorr).
import { nip19, type Event, type EventTemplate } from 'nostr-tools';
import { verifyEventFresh } from './verify-event.ts';
import { normalizeAddress, recoverAddress, stripPrefix, type Network } from './bchmsg.ts';

export const IDENTITY_KIND = 10011; // NIP-39 "external identities" list (replaceable: newest wins)
export const PLATFORM: Record<Network, string> = { mainnet: 'bch', chipnet: 'bchtest' };

export const verificationText = (pubkeyHex: string) =>
  `Verifying that I control the following Nostr public key: ${nip19.npubEncode(pubkeyHex)}`;

export interface Check { name: string; ok: boolean; detail?: string }
export interface ClaimResult {
  ok: boolean;
  pubkey: string;
  npub: string;
  address?: string; // full cashaddr with prefix
  eventId?: string;
  createdAt?: number;
  checks: Check[];
}

/** The `i` tag value for an address ("bch:qq…"), or undefined if the address is not a P2PKH cashaddr. */
export function identityName(address: string, network: Network = 'mainnet'): string | undefined {
  const a = normalizeAddress(address, network);
  return a && `${PLATFORM[network]}:${stripPrefix(a)}`;
}

export function claimTag(address: string, signature: string, network: Network = 'mainnet'): string[] {
  const name = identityName(address, network);
  if (!name) throw new Error('Not a P2PKH Bitcoin Cash address');
  return ['i', name, signature.trim()];
}

/**
 * The tags of a new kind 10011 that adds (or replaces) the claim for `address` and keeps everything else the
 * user already had in their list (other platforms, other BCH addresses), so publishing never wipes a profile.
 */
const sameClaim = (t: string[], name: string | undefined, network: Network) => {
  if (t[0] !== 'i' || typeof t[1] !== 'string' || !name) return false;
  const p = `${PLATFORM[network]}:`;
  if (!t[1].toLowerCase().startsWith(p)) return false;
  return identityName(t[1].slice(p.length), network) === name; // any spelling of the same address
};

export function mergeClaim(existing: Pick<Event, 'tags'> | undefined, tag: string[], network: Network = 'mainnet'): string[][] {
  const kept = (existing?.tags ?? []).filter((t) => !sameClaim(t, tag[1], network));
  return [...kept, tag];
}

/** The tags without the claim for `address` (unlinking = publishing the list without it). */
export function removeClaim(existing: Pick<Event, 'tags'> | undefined, address: string, network: Network = 'mainnet'): string[][] {
  const name = identityName(address, network);
  return (existing?.tags ?? []).filter((t) => !sameClaim(t, name, network));
}

export function identityTemplate(tags: string[][], existing?: Pick<Event, 'created_at'>, now = Date.now()): EventTemplate {
  // a replaceable event only wins if it is newer, so never go back in time behind the list we merged
  const created_at = Math.max(Math.floor(now / 1000), (existing?.created_at ?? 0) + 1);
  return { kind: IDENTITY_KIND, created_at, tags, content: '' };
}

/**
 * Verify every `bch` claim in a kind 10011 event, independently of where the event came from.
 * Rebuilds the signed text from the event's own author, so a claim copied into someone else's list fails.
 */
export const MAX_CLAIMS_CHECKED = 16; // a list with thousands of bch tags must not cost thousands of key recoveries

export function verifyClaims(event: Event, network: Network = 'mainnet'): ClaimResult[] {
  if (!event || typeof event !== 'object' || !verifyEventFresh(event)) {
    const pk = typeof event?.pubkey === 'string' ? event.pubkey : '';
    return [{ ok: false, pubkey: pk, npub: safeNpub(pk), checks: [{ name: 'Nostr signature valid', ok: false, detail: 'malformed or unsigned event' }] }];
  }
  const npub = safeNpub(event.pubkey);
  const base: Check[] = [];
  const kindOk = event.kind === IDENTITY_KIND;
  base.push({ name: 'Event is a NIP-39 identity list (kind 10011)', ok: kindOk, detail: `kind ${event.kind}` });
  const sigOk = true; // checked above
  base.push({ name: 'Nostr signature valid (the Nostr key published this address)', ok: sigOk, detail: npub });
  const prefix = `${PLATFORM[network]}:`;
  const claims = event.tags.filter((t) => t[0] === 'i' && typeof t[1] === 'string' && t[1].startsWith(prefix)).slice(0, MAX_CLAIMS_CHECKED);
  if (!claims.length) return [{ ok: false, pubkey: event.pubkey, npub, eventId: event.id, createdAt: event.created_at, checks: [...base, { name: 'Contains a bch claim', ok: false }] }];
  return claims.map((t) => {
    const checks = [...base];
    const parsed = normalizeAddress(t[1].slice(prefix.length), network);
    // only the canonical form counts (lowercase q…, no prefix): otherwise unlinking and #i lookups would miss it
    const address = parsed && t[1] === identityName(parsed, network) ? parsed : undefined;
    checks.push({ name: 'Claimed value is a P2PKH Bitcoin Cash address in canonical form (bch:q…)', ok: !!address, detail: t[1] });
    const text = verificationText(event.pubkey);
    const signer = address && typeof t[2] === 'string' ? recoverAddress(text, t[2], network) : undefined;
    checks.push({
      name: 'BCH signature over the NIP-39 text recovers to that address (the BCH key named this Nostr key)',
      ok: !!signer && signer === address,
      detail: signer ? `signed by ${signer}` : 'signature missing or malformed',
    });
    return { ok: checks.every((c) => c.ok), pubkey: event.pubkey, npub, address, eventId: event.id, createdAt: event.created_at, checks };
  });
}

function safeNpub(hex: string): string {
  try { return nip19.npubEncode(hex); } catch { return hex; }
}

/** Accepts npub…, nprofile… or 64-hex; returns the hex pubkey. */
export function toPubkeyHex(input: string): string | undefined {
  const s = input.trim();
  if (/^[0-9a-f]{64}$/i.test(s)) return s.toLowerCase();
  try {
    const d = nip19.decode(s);
    if (d.type === 'npub') return d.data as string;
    if (d.type === 'nprofile') return (d.data as { pubkey: string }).pubkey;
  } catch { /* not bech32 */ }
  return undefined;
}
