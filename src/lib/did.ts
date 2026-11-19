// Interop helpers: a W3C DID view of a verified binding, and identity-based payment requests.
import { nip19 } from 'nostr-tools';

/** CAIP-2 chain id of Bitcoin Cash mainnet (ChainAgnostic namespaces, bip122: first BCH block 478559). */
export const BCH_CAIP2 = 'bip122:000000000000000000651ef99cb9fcbe';

/**
 * A minimal DID document for a VERIFIED binding: the Nostr key as `did:nostr`, the BCH address as `did:pkh`
 * (CAIP-10), linked both ways through `alsoKnownAs`. Informational: the proof is still the NIP-39 claim.
 */
export function didDocument(pubkeyHex: string, address: string) {
  const nostr = `did:nostr:${pubkeyHex}`;
  const pkh = `did:pkh:${BCH_CAIP2}:${address}`;
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: nostr,
    alsoKnownAs: [pkh, `nostr:${nip19.npubEncode(pubkeyHex)}`],
    verificationMethod: [{
      id: `${nostr}#nostr-key`,
      type: 'SchnorrSecp256k1VerificationKey2019',
      controller: nostr,
      publicKeyHex: pubkeyHex,
    }, {
      id: `${nostr}#bch-address`,
      type: 'BlockchainVerificationMethod2021',
      controller: nostr,
      blockchainAccountId: `${BCH_CAIP2}:${address}`,
    }],
    authentication: [`${nostr}#nostr-key`],
    assertionMethod: [`${nostr}#nostr-key`, `${nostr}#bch-address`],
  };
}

/** BIP21-style payment request to a verified address (amount in BCH, optional). */
export function paymentUri(address: string, amountBch?: number, label?: string): string {
  const q = new URLSearchParams();
  if (amountBch && amountBch > 0) q.set('amount', amountBch.toFixed(8).replace(/\.?0+$/, ''));
  if (label) q.set('label', label);
  const s = q.toString();
  return s ? `${address}?${s}` : address;
}
