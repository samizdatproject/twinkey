import { describe, expect, it } from 'vitest';
import { didDocument, paymentUri, BCH_CAIP2 } from '../src/lib/did.ts';

describe('DID view and payment URI', () => {
  it('uses a CAIP-10 account id without the cashaddr prefix', () => {
    const doc = didDocument('a'.repeat(64), 'bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r');
    expect(doc.alsoKnownAs[0]).toBe(`did:pkh:${BCH_CAIP2}:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r`);
    expect(doc.verificationMethod[1]!.blockchainAccountId!.split(':').length).toBe(3); // namespace:reference:address
    expect(/^[-.%a-zA-Z0-9]{1,128}$/.test(doc.verificationMethod[1]!.blockchainAccountId!.split(':')[2])).toBe(true);
  });
  it('builds BIP21 URIs', () => {
    expect(paymentUri('bitcoincash:qq1')).toBe('bitcoincash:qq1');
    expect(paymentUri('bitcoincash:qq1', 0.0015)).toBe('bitcoincash:qq1?amount=0.0015');
    expect(paymentUri('bitcoincash:qq1', 1)).toBe('bitcoincash:qq1?amount=1');
  });
});
