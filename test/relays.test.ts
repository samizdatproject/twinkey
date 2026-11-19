import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generatePrivateKey } from '@bitauth/libauth';
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools';
import { addressOf, signMessage } from '../src/lib/bchmsg.ts';
import { claimTag, identityTemplate, mergeClaim, removeClaim, verificationText } from '../src/lib/claim.ts';
import { discoverByAddress, discoverByPubkey, fetchIdentityList, publish } from '../src/lib/relays.ts';
import { startMockRelay } from './mock-relay.ts';

let a: Awaited<ReturnType<typeof startMockRelay>>;
let b: Awaited<ReturnType<typeof startMockRelay>>;
beforeAll(async () => { a = await startMockRelay(); b = await startMockRelay(); });
afterAll(async () => { await a.close(); await b.close(); });

function identity() {
  const bch = generatePrivateKey();
  const sk = generateSecretKey();
  const pub = getPublicKey(sk);
  return { bch, sk, pub, address: addressOf(bch), sig: signMessage(bch, verificationText(pub)) };
}

describe('publish and discover over relays', () => {
  it('publishes to several relays and finds the binding by Nostr key and by BCH address', async () => {
    const id = identity();
    const ev = finalizeEvent(identityTemplate([claimTag(id.address, id.sig)]), id.sk);
    const res = await publish(ev, [a.url, b.url]);
    expect(res.accepted.sort()).toEqual([a.url, b.url].sort());

    const byKey = await discoverByPubkey(id.pub, 'mainnet', [a.url, b.url], 2000);
    expect(byKey.results.map((r) => [r.ok, r.address])).toEqual([[true, id.address]]);

    const byAddr = await discoverByAddress(id.address.toUpperCase(), 'mainnet', [b.url], 2000);
    expect(byAddr.map((r) => [r.ok, r.pubkey])).toEqual([[true, id.pub]]);
  });

  it('keeps existing identities when adding the claim (fetch, merge, newer created_at)', async () => {
    const id = identity();
    const first = finalizeEvent(identityTemplate([['i', 'github:alice', 'gist1']], undefined, Date.now() + 60_000), id.sk);
    await publish(first, [a.url]);
    const existing = await fetchIdentityList(id.pub, [a.url], 2000);
    const next = finalizeEvent(identityTemplate(mergeClaim(existing, claimTag(id.address, id.sig)), existing), id.sk);
    expect((await publish(next, [a.url])).accepted).toEqual([a.url]);
    const latest = await fetchIdentityList(id.pub, [a.url], 2000);
    expect(latest?.id).toBe(next.id);
    expect(latest?.tags).toContainEqual(['i', 'github:alice', 'gist1']);
  });

  it('unlinking (newer list without the claim) wins even if a relay still has the old copy', async () => {
    const id = identity();
    const linked = finalizeEvent(identityTemplate([claimTag(id.address, id.sig)], undefined, Date.now() - 10_000), id.sk);
    await publish(linked, [a.url, b.url]);
    const unlinked = finalizeEvent(identityTemplate(removeClaim(linked, id.address), linked), id.sk);
    await publish(unlinked, [a.url]); // relay b never hears about it and keeps the linked copy
    expect(await discoverByAddress(id.address, 'mainnet', [a.url, b.url], 2000)).toEqual([]);
    expect((await discoverByPubkey(id.pub, 'mainnet', [a.url, b.url], 2000)).results.every((r) => !r.ok)).toBe(true);
  });

  it('a forged claim stored on a relay is found but reported as invalid', async () => {
    const victim = identity();
    const thief = identity();
    const forged = finalizeEvent(identityTemplate([claimTag(victim.address, victim.sig)]), thief.sk);
    a.inject(forged);
    const found = await discoverByAddress(victim.address, 'mainnet', [a.url], 2000);
    expect(found.find((r) => r.pubkey === thief.pub)?.ok).toBe(false);
  });

  it('an unreachable relay does not block the others', async () => {
    const id = identity();
    await publish(finalizeEvent(identityTemplate([claimTag(id.address, id.sig)]), id.sk), [a.url]);
    const t0 = Date.now();
    const r = await discoverByPubkey(id.pub, 'mainnet', ['ws://127.0.0.1:1', a.url], 2000);
    expect(r.results[0]?.ok).toBe(true);
    expect(Date.now() - t0).toBeLessThan(2500);
  });
});
