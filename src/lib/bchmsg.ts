// Bitcoin Signed Message on Bitcoin Cash: the format Electron Cash ("Sign/verify message"), mainnet-js and the
// Paytaca wallet use. hash = sha256d("\x18Bitcoin Signed Message:\n" || compactSize(len) || utf8(message)),
// signature = base64(header || r || s) with header 27 + recoveryId (+4 for a compressed key).
import {
  base64ToBin, bigIntToCompactUint, binToBase64, decodeCashAddress, encodeCashAddress, hash160, secp256k1, sha256,
  utf8ToBin,
} from '@bitauth/libauth';

const MAGIC = utf8ToBin('\x18Bitcoin Signed Message:\n');

export function messageHash(message: string): Uint8Array {
  const msg = utf8ToBin(message);
  const data = new Uint8Array([...MAGIC, ...bigIntToCompactUint(BigInt(msg.length)), ...msg]);
  return sha256.hash(sha256.hash(data));
}

/** Sign with a 32-byte private key (compressed public key, header 31–34), as Electron Cash and Paytaca do. */
export function signMessage(privateKey: Uint8Array, message: string): string {
  const rs = secp256k1.signMessageHashRecoverableCompact(privateKey, messageHash(message));
  if (typeof rs === 'string') throw new Error(rs);
  return binToBase64(new Uint8Array([31 + rs.recoveryId, ...rs.signature]));
}

export type Network = 'mainnet' | 'chipnet';
const PREFIX: Record<Network, 'bitcoincash' | 'bchtest'> = { mainnet: 'bitcoincash', chipnet: 'bchtest' };

/**
 * The P2PKH cashaddr whose key made `signature` over `message`, or undefined if the signature is malformed.
 * Accepts compressed (header 31–34) and uncompressed (27–30) keys, like Electron Cash.
 */
export function recoverAddress(message: string, signature: string, network: Network = 'mainnet'): string | undefined {
  let sig: Uint8Array;
  try {
    sig = base64ToBin(signature.trim());
  } catch {
    return undefined;
  }
  if (sig.length !== 65) return undefined;
  const header = sig[0];
  if (header < 27 || header > 34) return undefined;
  const compressed = header >= 31;
  const recoveryId = ((header - 27) & 3) as 0 | 1 | 2 | 3;
  const rs = sig.slice(1);
  const hash = messageHash(message);
  const pub = compressed
    ? secp256k1.recoverPublicKeyCompressed(rs, recoveryId, hash)
    : secp256k1.recoverPublicKeyUncompressed(rs, recoveryId, hash);
  if (typeof pub === 'string') return undefined;
  // recovery already implies a valid signature for `pub`; checking again guards against library edge cases
  if (!secp256k1.verifySignatureCompact(rs, pub, hash)) return undefined;
  return encodeCashAddress({ prefix: PREFIX[network], type: 'p2pkh', payload: hash160(pub) }).address;
}

/** Normalise any cashaddr form (with or without prefix, any case, q… or token-aware z…) to the plain P2PKH form. */
export function normalizeAddress(address: string, network: Network = 'mainnet'): string | undefined {
  const a = address.trim().toLowerCase();
  const withPrefix = a.includes(':') ? a : `${PREFIX[network]}:${a}`;
  const d = decodeCashAddress(withPrefix);
  if (typeof d === 'string' || d.prefix !== PREFIX[network]) return undefined;
  if (d.type !== 'p2pkh' && d.type !== 'p2pkhWithTokens') return undefined; // message signatures prove a key, not a script
  return encodeCashAddress({ prefix: PREFIX[network], type: 'p2pkh', payload: d.payload }).address;
}

/** True when `signature` over `message` was made by the key of `address` (any cashaddr form). */
export function verifyMessage(address: string, signature: string, message: string, network: Network = 'mainnet'): boolean {
  const want = normalizeAddress(address, network);
  return !!want && recoverAddress(message, signature, network) === want;
}

/** The P2PKH address of a private key (compressed), for the demo wallet. */
export function addressOf(privateKey: Uint8Array, network: Network = 'mainnet'): string {
  const pub = secp256k1.derivePublicKeyCompressed(privateKey);
  if (typeof pub === 'string') throw new Error(pub);
  return encodeCashAddress({ prefix: PREFIX[network], type: 'p2pkh', payload: hash160(pub) }).address;
}

/** Address without the prefix, as used in the NIP-39 identity name. */
export const stripPrefix = (address: string) => address.slice(address.indexOf(':') + 1);
