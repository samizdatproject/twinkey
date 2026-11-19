import { describe, expect, it } from 'vitest';
import { generatePrivateKey } from '@bitauth/libauth';
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools';
import { addressOf, signMessage } from '../src/lib/bchmsg.ts';
import {
  authHeader, authTemplate, bchLoginText, newChallenge, parseAuthHeader, verifyAuth, verifyBchStepUp,
} from '../src/lib/auth.ts';

const APP = 'https://app.example/login';

describe('login (NIP-98 challenge-response)', () => {
  it('accepts a fresh signed challenge once, then refuses the replay', () => {
    const sk = generateSecretKey();
    const used = new Set<string>();
    const c = newChallenge(APP);
    const ev = finalizeEvent(authTemplate(c), sk);
    const r = verifyAuth(ev, c, { used });
    expect(r.ok).toBe(true);
    expect(r.pubkey).toBe(getPublicKey(sk));
    expect(verifyAuth(ev, c, { used }).ok).toBe(false);
  });

  it('refuses another challenge\'s event, another app, old events and expired challenges', () => {
    const sk = generateSecretKey();
    const used = new Set<string>();
    const c1 = newChallenge(APP);
    const c2 = newChallenge(APP);
    expect(verifyAuth(finalizeEvent(authTemplate(c1), sk), c2, { used }).ok).toBe(false);
    const evil = newChallenge('https://evil.example/login');
    expect(verifyAuth(finalizeEvent(authTemplate({ ...evil, url: evil.url }), sk), { ...evil, url: c1.url }, { used }).ok).toBe(false);
    const old = finalizeEvent(authTemplate(c1, Date.now() - 120_000), sk);
    expect(verifyAuth(old, c1, { used }).ok).toBe(false);
    const short = newChallenge(APP, 1, Date.now() - 5_000);
    expect(verifyAuth(finalizeEvent(authTemplate(short), sk), short, { used }).ok).toBe(false);
    const wrongMethod = finalizeEvent({ ...authTemplate(c1), tags: [['u', c1.url], ['method', 'GET']] }, sk);
    expect(verifyAuth(wrongMethod, c1, { used }).ok).toBe(false);
    expect(used.size).toBe(0); // nothing was accepted
  });

  it('refuses a tampered event', () => {
    const sk = generateSecretKey();
    const c = newChallenge(APP);
    const ev = finalizeEvent(authTemplate(c), sk);
    expect(verifyAuth({ ...ev, pubkey: getPublicKey(generateSecretKey()) }, c, { used: new Set() }).ok).toBe(false);
  });

  it('BCH step-up: the bound BCH key signs the login text for this nonce and this Nostr key', () => {
    const sk = generateSecretKey();
    const pub = getPublicKey(sk);
    const bch = generatePrivateKey();
    const addr = addressOf(bch);
    const c = newChallenge(APP);
    const sig = signMessage(bch, bchLoginText(c, pub));
    expect(bchLoginText(c, pub)).toMatch(/^Log in to https:\/\/app\.example as npub1[a-z0-9]+ with nonce [0-9a-f]{32}$/);
    expect(verifyBchStepUp(c, pub, addr, sig).ok).toBe(true);
    expect(verifyBchStepUp(newChallenge(APP), pub, addr, sig).ok).toBe(false); // other nonce
    expect(verifyBchStepUp(c, getPublicKey(generateSecretKey()), addr, sig).ok).toBe(false); // other Nostr key
    expect(verifyBchStepUp(c, pub, addressOf(generatePrivateKey()), sig).ok).toBe(false); // other address
  });

  it('Authorization header round-trips', () => {
    const ev = finalizeEvent(authTemplate(newChallenge(APP)), generateSecretKey());
    expect(JSON.stringify(parseAuthHeader(authHeader(ev)))).toBe(JSON.stringify(ev));
    expect(parseAuthHeader('Bearer x')).toBeUndefined();
    expect(parseAuthHeader('Nostr %%%')).toBeUndefined();
  });
});

describe('malformed login input', () => {
  it('returns ok:false instead of throwing', () => {
    const c = newChallenge(APP);
    for (const bad of [{}, { tags: 'x' }, { kind: 27235, tags: [[ 'u', 5 ]] }, null]) {
      expect(verifyAuth(bad as never, c, { used: new Set() }).ok).toBe(false);
    }
  });
});
