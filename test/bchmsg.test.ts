import { describe, expect, it } from 'vitest';
import { decodeBase58Address, decodePrivateKeyWif, encodeCashAddress, generatePrivateKey } from '@bitauth/libauth';
import { addressOf, normalizeAddress, recoverAddress, signMessage, verifyMessage } from '../src/lib/bchmsg.ts';
// @ts-expect-error plain JS vendored for the cross-check
import { SignedMessage } from './vendor/mainnet-js-signed.js';

const legacyToCash = (legacy: string) => {
  const d = decodeBase58Address(legacy);
  if (typeof d === 'string') throw new Error(d);
  return encodeCashAddress({ prefix: 'bitcoincash', type: 'p2pkh', payload: d.payload }).address;
};
const wifKey = (wif: string) => {
  const d = decodePrivateKeyWif(wif);
  if (typeof d === 'string') throw new Error(d);
  return d.privateKey;
};

// Electron Cash electroncash/tests/test_bitcoin.py::test_msg_signing (both nonce variants, compressed and uncompressed keys)
const EC = {
  msg1: 'Chancellor on brink of second bailout for banks',
  wif1: 'L1TnU2zbNaAqMoVh65Cyvmcjzbrj41Gs9iTLcWbpJCMynXuap6UN',
  addr1: legacyToCash('15hETetDmcXm1mM4sEf7U2KXC9hDHFMSzz'),
  sigs1: ['H/9jMOnj4MFbH3d7t4yCQ9i7DgZU/VZ278w3+ySv2F4yIsdqjsc5ng3kmN8OZAThgyfCZOQxZCWza9V5XzlVY0Y=', 'IA+oq/uGz4kKA2bNgxPcM+T216abyUiBhofMg1J8fC5BLAbbIpF2toCHaO7/LQAxhQBtu5D6ROq1JjXiRwPAASg='],
  msg2: 'Electrum',
  addr2: legacyToCash('1GPHVTY8UD9my6jyP4tb2TYJwUbDetyNC6'), // uncompressed key
  sigs2: ['G84dmJ8TKIDKMT9qBRhpX2sNmR0y5t+POcYnFFJCs66lJmAs3T8A6Sbpx7KA6yTQ9djQMabwQXRrDomOkIKGn18=', 'HP+MT0B/Ga++0DEXDJE0oBb1DEsBMX0j+i2mbyEI4nwVMZkwc/pHgL2KlntotC+k8uU8y/M4YAdO4n7vfuUVL8A='],
};

describe('Bitcoin Signed Message', () => {
  it('verifies the Electron Cash test vectors (compressed and uncompressed keys)', () => {
    for (const s of EC.sigs1) expect(verifyMessage(EC.addr1, s, EC.msg1)).toBe(true);
    for (const s of EC.sigs2) expect(verifyMessage(EC.addr2, s, EC.msg2)).toBe(true);
    expect(verifyMessage(EC.addr2, EC.sigs1[0], EC.msg1)).toBe(false);
    expect(verifyMessage(EC.addr1, EC.sigs1[0], EC.msg2)).toBe(false);
  });

  it('signs like Electron Cash (RFC 6979 nonce, same bytes as the libsecp vector)', () => {
    const sig = signMessage(wifKey(EC.wif1), EC.msg1);
    expect(EC.sigs1).toContain(sig);
    expect(addressOf(wifKey(EC.wif1))).toBe(EC.addr1);
  });

  it('matches the Paytaca wallet signer both ways (mainnet-js SignedMessage)', () => {
    for (let i = 0; i < 20; i++) {
      const key = generatePrivateKey();
      const addr = addressOf(key);
      const msg = `Verifying that I control the following Nostr public key: npub${i}${'x'.repeat(i * 7)}`;
      const ours = signMessage(key, msg);
      const theirs = SignedMessage.sign(msg, key).signature as string;
      expect(ours).toBe(theirs);
      expect(SignedMessage.verify(msg, ours, addr).valid).toBe(true);
      expect(verifyMessage(addr, theirs, msg)).toBe(true);
    }
  });

  it('handles non-ASCII text by its UTF-8 byte length', () => {
    const key = generatePrivateKey();
    const msg = 'naïve ✓ 日本 '.repeat(30); // > 253 bytes: two-byte compactSize
    const sig = signMessage(key, msg);
    expect(SignedMessage.verify(msg, sig, addressOf(key)).valid).toBe(true);
    expect(verifyMessage(addressOf(key), sig, msg)).toBe(true);
  });

  it('rejects malformed signatures without throwing', () => {
    expect(recoverAddress('x', 'not base64!!')).toBeUndefined();
    expect(recoverAddress('x', '')).toBeUndefined();
    expect(recoverAddress('x', btoa('a'.repeat(64)))).toBeUndefined();
    const bad = Uint8Array.from(atob(EC.sigs1[0]), (c) => c.charCodeAt(0));
    bad[0] = 40; // header out of range
    expect(recoverAddress(EC.msg1, btoa(String.fromCharCode(...bad)))).toBeUndefined();
    bad[0] = 31;
    bad[10] ^= 1; // flipped bit: recovers some other key
    expect(verifyMessage(EC.addr1, btoa(String.fromCharCode(...bad)), EC.msg1)).toBe(false);
  });

  it('normalises address forms and refuses script / wrong-network addresses', () => {
    const key = generatePrivateKey();
    const a = addressOf(key);
    expect(normalizeAddress(a.toUpperCase())).toBe(a);
    expect(normalizeAddress(a.slice('bitcoincash:'.length))).toBe(a);
    const z = encodeCashAddress({ prefix: 'bitcoincash', type: 'p2pkhWithTokens', payload: new Uint8Array(20).fill(7) }).address;
    expect(normalizeAddress(z)).toBe(encodeCashAddress({ prefix: 'bitcoincash', type: 'p2pkh', payload: new Uint8Array(20).fill(7) }).address);
    const p2sh = encodeCashAddress({ prefix: 'bitcoincash', type: 'p2sh', payload: new Uint8Array(20).fill(7) }).address;
    expect(normalizeAddress(p2sh)).toBeUndefined();
    expect(normalizeAddress(addressOf(key, 'chipnet'))).toBeUndefined();
    expect(normalizeAddress('bitcoincash:qqqq')).toBeUndefined();
  });
});
