import { describe, expect, it } from 'vitest';
import { generatePrivateKey } from '@bitauth/libauth';
import { finalizeEvent, generateSecretKey, getPublicKey, nip19 } from 'nostr-tools';
import { addressOf, signMessage, stripPrefix } from '../src/lib/bchmsg.ts';
import {
  claimTag, identityName, identityTemplate, mergeClaim, removeClaim, toPubkeyHex, verificationText, verifyClaims,
} from '../src/lib/claim.ts';

function makeIdentity() {
  const bchKey = generatePrivateKey();
  const nostrKey = generateSecretKey();
  const pubkey = getPublicKey(nostrKey);
  const address = addressOf(bchKey);
  const sig = signMessage(bchKey, verificationText(pubkey));
  return { bchKey, nostrKey, pubkey, address, sig };
}

describe('NIP-39 bch claim', () => {
  it('uses the exact NIP-39 verification text (one ASCII line)', () => {
    const { pubkey } = makeIdentity();
    const t = verificationText(pubkey);
    expect(t).toBe(`Verifying that I control the following Nostr public key: ${nip19.npubEncode(pubkey)}`);
    expect(/^[\x20-\x7e]+$/.test(t)).toBe(true);
  });

  it('a correct binding verifies, with every check passing', () => {
    const id = makeIdentity();
    const ev = finalizeEvent(identityTemplate([claimTag(id.address, id.sig)]), id.nostrKey);
    expect(ev.tags[0]).toEqual(['i', `bch:${stripPrefix(id.address)}`, id.sig]);
    const [r] = verifyClaims(ev);
    expect(r.ok).toBe(true);
    expect(r.address).toBe(id.address);
    expect(r.checks.every((c) => c.ok)).toBe(true);
  });

  it('a claim copied into another Nostr key\'s list fails (the BCH signature names the original key)', () => {
    const victim = makeIdentity();
    const thief = generateSecretKey();
    const ev = finalizeEvent(identityTemplate([claimTag(victim.address, victim.sig)]), thief);
    expect(verifyClaims(ev)[0].ok).toBe(false);
  });

  it('claiming someone else\'s address with your own signature fails', () => {
    const me = makeIdentity();
    const other = makeIdentity();
    const ev = finalizeEvent(identityTemplate([claimTag(other.address, me.sig)]), me.nostrKey);
    const [r] = verifyClaims(ev);
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name.startsWith('BCH signature'))?.detail).toContain(me.address);
  });

  it('a tampered event fails the Nostr signature check', () => {
    const id = makeIdentity();
    const ev = finalizeEvent(identityTemplate([claimTag(id.address, id.sig)]), id.nostrKey);
    const tampered = { ...ev, tags: [['i', `bch:${stripPrefix(makeIdentity().address)}`, id.sig]] };
    expect(verifyClaims(tampered)[0].ok).toBe(false);
    expect(verifyClaims({ ...ev, kind: 0 })[0].ok).toBe(false);
  });

  it('garbage proofs and non-P2PKH values fail without throwing', () => {
    const id = makeIdentity();
    for (const tag of [['i', `bch:${stripPrefix(id.address)}`], ['i', `bch:${stripPrefix(id.address)}`, 'zzz'], ['i', 'bch:pzzzz', id.sig]]) {
      const ev = finalizeEvent(identityTemplate([tag]), id.nostrKey);
      expect(verifyClaims(ev)[0].ok).toBe(false);
    }
    const none = finalizeEvent(identityTemplate([['i', 'github:someone', 'gist']]), id.nostrKey);
    expect(verifyClaims(none)[0].ok).toBe(false);
  });

  it('merging keeps the user\'s other identities and replaces only this address', () => {
    const id = makeIdentity();
    const existing = { tags: [['i', 'github:alice', 'abc'], ['i', `bch:${stripPrefix(id.address)}`, 'old'], ['i', 'bch:qother', 'x']], created_at: 2_000_000_000 };
    const tags = mergeClaim(existing, claimTag(id.address, id.sig));
    expect(tags).toContainEqual(['i', 'github:alice', 'abc']);
    expect(tags).toContainEqual(['i', 'bch:qother', 'x']);
    expect(tags.filter((t) => t[1] === `bch:${stripPrefix(id.address)}`)).toEqual([claimTag(id.address, id.sig)]);
    expect(identityTemplate(tags, existing, 1_000).created_at).toBe(2_000_000_001); // never older than what it replaces
    expect(removeClaim({ tags }, id.address)).not.toContainEqual(claimTag(id.address, id.sig));
  });

  it('the claim name is the same for every address form', () => {
    const { address } = makeIdentity();
    const want = `bch:${stripPrefix(address)}`;
    expect(identityName(address)).toBe(want);
    expect(identityName(address.toUpperCase())).toBe(want);
    expect(identityName(stripPrefix(address))).toBe(want);
  });

  it('parses npub, nprofile and hex', () => {
    const { pubkey } = makeIdentity();
    expect(toPubkeyHex(nip19.npubEncode(pubkey))).toBe(pubkey);
    expect(toPubkeyHex(nip19.nprofileEncode({ pubkey }))).toBe(pubkey);
    expect(toPubkeyHex(pubkey.toUpperCase())).toBe(pubkey);
    expect(toPubkeyHex('nsec1whatever')).toBeUndefined();
  });
});

describe('cached-verification trap', () => {
  it('a spread copy of a verified event with a swapped key or tags is NOT accepted', () => {
    const id = makeIdentity();
    const ev = finalizeEvent(identityTemplate([claimTag(id.address, id.sig)]), id.nostrKey);
    expect(verifyClaims(ev)[0].ok).toBe(true); // marks ev as verified inside nostr-tools
    const other = makeIdentity();
    const forged = { ...ev, pubkey: other.pubkey, tags: [claimTag(other.address, other.sig)] };
    expect(verifyClaims(forged)[0].ok).toBe(false);
  });
});
