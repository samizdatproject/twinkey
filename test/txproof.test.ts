import { describe, expect, it } from 'vitest';
import {
  encodeTransaction, generatePrivateKey, generateTransaction, hexToBin, binToHex, walletTemplateP2pkhNonHd,
  walletTemplateToCompilerBCH, type Transaction,
} from '@bitauth/libauth';
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools';
import { addressOf } from '../src/lib/bchmsg.ts';
import { claimTag, identityTemplate, verificationText, verifyClaims, verifyClaimsOnline } from '../src/lib/claim.ts';
import { buildCommitment, buildPayment, commitmentBytecode, lockingBytecodeOf, txidOf, verifyTxProof, type UnsignedTx } from '../src/lib/txproof.ts';

const compiler = walletTemplateToCompilerBCH(walletTemplateP2pkhNonHd);

/** A fake previous transaction paying `sats` to `address` (its own inputs are irrelevant to the proof). */
function fundingTx(address: string, sats: bigint) {
  const tx: Transaction = {
    version: 2, locktime: 0,
    inputs: [{ outpointTransactionHash: crypto.getRandomValues(new Uint8Array(32)), outpointIndex: 0, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array([0x51]) }],
    outputs: [{ lockingBytecode: lockingBytecodeOf(address), valueSatoshis: sats }],
  };
  const hex = binToHex(encodeTransaction(tx));
  return { hex, txid: txidOf(hex) };
}

/** Sign every input with `key` (what the wallet does). */
function sign(u: UnsignedTx, key: Uint8Array): string {
  const r = generateTransaction({
    version: u.transaction.version,
    locktime: u.transaction.locktime,
    outputs: u.transaction.outputs,
    inputs: u.sourceOutputs.map((s) => ({
      outpointTransactionHash: s.outpointTransactionHash,
      outpointIndex: s.outpointIndex,
      sequenceNumber: s.sequenceNumber,
      unlockingBytecode: { compiler, data: { keys: { privateKeys: { key } } }, script: 'unlock', valueSatoshis: s.valueSatoshis },
    })),
  });
  if (!r.success) throw new Error(JSON.stringify(r.errors));
  return binToHex(encodeTransaction(r.transaction));
}

function setup() {
  const key = generatePrivateKey();
  const address = addressOf(key);
  const sk = generateSecretKey();
  const pubkey = getPublicKey(sk);
  const fund = fundingTx(address, 5000n);
  const store = new Map<string, string>([[fund.txid, fund.hex]]);
  const fetchTx = async (id: string) => { const h = store.get(id); if (!h) throw new Error('unknown tx'); return h; };
  return { key, address, sk, pubkey, fund, store, fetchTx };
}

describe('on-chain proof (WizardConnect wallets)', () => {
  it('a signed commitment transaction proves the binding', async () => {
    const s = setup();
    const text = verificationText(s.pubkey);
    const u = buildCommitment(s.address, [{ txid: s.fund.txid, vout: 0, satoshis: 5000n, height: 1 }], text);
    expect(binToHex(u.transaction.outputs[0].lockingBytecode)).toBe(binToHex(commitmentBytecode(text)));
    expect(u.transaction.outputs[1].valueSatoshis).toBe(5000n - u.fee);
    const hex = sign(u, s.key);
    s.store.set(txidOf(hex), hex);
    const check = await verifyTxProof(`tx:${txidOf(hex)}`, s.address, text, s.fetchTx);
    expect(check).toMatchObject({ ok: true });

    // end to end through a NIP-39 claim
    const ev = finalizeEvent(identityTemplate([claimTag(s.address, `tx:${txidOf(hex)}`)]), s.sk);
    expect(verifyClaims(ev)[0].ok).toBe(false); // offline: pending
    const [r] = await verifyClaimsOnline(ev, 'mainnet', s.fetchTx);
    expect(r.ok).toBe(true);
    expect(r.proofType).toBe('tx');
  });

  it('rejects: other Nostr key, other address, tampered server data, wrong signer', async () => {
    const s = setup();
    const text = verificationText(s.pubkey);
    const u = buildCommitment(s.address, [{ txid: s.fund.txid, vout: 0, satoshis: 5000n, height: 1 }], text);
    const hex = sign(u, s.key);
    const txid = txidOf(hex);
    s.store.set(txid, hex);
    // the proof names s.pubkey, so it cannot be claimed by another key
    expect((await verifyTxProof(`tx:${txid}`, s.address, verificationText(getPublicKey(generateSecretKey())), s.fetchTx)).ok).toBe(false);
    // nor for another address
    expect((await verifyTxProof(`tx:${txid}`, addressOf(generatePrivateKey()), text, s.fetchTx)).ok).toBe(false);
    // a server returning something else under this txid
    const lying = async (id: string) => (id === txid ? hex.slice(0, -2) + '01' : s.fetchTx(id));
    expect((await verifyTxProof(`tx:${txid}`, s.address, text, lying)).ok).toBe(false);
    // signed by a different key while spending the claimed address's coin: the VM refuses it
    const forged = sign(u, generatePrivateKey());
    s.store.set(txidOf(forged), forged);
    const r = await verifyTxProof(`tx:${txidOf(forged)}`, s.address, text, s.fetchTx);
    expect(r.ok).toBe(false);
    expect(r.detail).toMatch(/signature check failed/);
    // unknown tx and junk proofs
    expect((await verifyTxProof(`tx:${'0'.repeat(64)}`, s.address, text, s.fetchTx)).ok).toBe(false);
    expect((await verifyTxProof('tx:zz', s.address, text, s.fetchTx)).ok).toBe(false);
  });

  it('refuses to build with too little money, and builds payments with change', () => {
    const s = setup();
    expect(() => buildCommitment(s.address, [{ txid: s.fund.txid, vout: 0, satoshis: 600n, height: 1 }], 'x'.repeat(120))).toThrow(/Not enough/);
    const to = addressOf(generatePrivateKey());
    const p = buildPayment([{ txid: s.fund.txid, vout: 0, satoshis: 5000n, height: 1, address: s.address }], to, 1000n, s.address);
    expect(p.transaction.outputs.map((o) => o.valueSatoshis)).toEqual([1000n, 5000n - 1000n - p.fee]);
    expect(binToHex(p.transaction.outputs[0].lockingBytecode)).toBe(binToHex(lockingBytecodeOf(to)));
    expect(() => buildPayment([{ txid: s.fund.txid, vout: 0, satoshis: 900n, height: 1, address: s.address }], to, 1000n, s.address)).toThrow(/Not enough/);
    void hexToBin;
  });
});

describe('WizardConnect request encoding', () => {
  it('is JSON-serialisable and decodes back to the same transaction (the bug a real Paytaca test found)', async () => {
    const { wizardSignRequest } = await import('../src/lib/wcrequest.ts');
    const { parseExtendedJson } = await import('@wizardconnect/core');
    const s = setup();
    const u = buildCommitment(s.address, [{ txid: s.fund.txid, vout: 0, satoshis: 5000n, height: 1 }], verificationText(s.pubkey));
    expect(() => JSON.stringify(u.sourceOutputs)).toThrow(/BigInt/); // what we used to send
    const req = wizardSignRequest(u, 'test');
    const json = JSON.stringify(req);
    const back = parseExtendedJson(json);
    expect(back.transaction).toBe(binToHex(encodeTransaction(u.transaction)));
    expect(BigInt(back.sourceOutputs[0].valueSatoshis)).toBe(5000n);
  });
});
