// On-chain proof ("BCH-backed identity commitment"), for wallets that can sign transactions but not messages
// (WizardConnect: Paytaca, Selene, Cashonize). The wallet spends a coin of the claimed address in a transaction whose
// OP_RETURN carries the exact NIP-39 verification text; the claim's proof is then "tx:<txid>".
//
// Verification needs no trusted server: fetch the transaction and the coins it spends from any Electrum server,
// check every fetched transaction against its txid, then run the BCH virtual machine on the inputs. A valid input
// spending a P2PKH coin of the claimed address means that key signed a transaction naming this Nostr key.
import {
  binToHex, cashAddressToLockingBytecode, createVirtualMachineBCH, decodeTransaction, encodeDataPush,
  encodeTransaction, hashTransactionUiOrder, hexToBin, type Output, type Transaction,
} from '@bitauth/libauth';
import type { Check } from './claim.ts';
import type { ElectrumCall, Utxo } from './electrum.ts';
import { getTransactionHex } from './electrum.ts';

export const TX_PROOF_PREFIX = 'tx:';
export const DUST = 546n;

export const isTxProof = (proof: string | undefined) => typeof proof === 'string' && /^tx:[0-9a-f]{64}$/.test(proof);

/** OP_RETURN <text>: the commitment output's locking bytecode. */
export const commitmentBytecode = (text: string) => new Uint8Array([0x6a, ...encodeDataPush(new TextEncoder().encode(text))]);

export function lockingBytecodeOf(address: string): Uint8Array {
  const r = cashAddressToLockingBytecode(address);
  if (typeof r === 'string') throw new Error(r);
  return r.bytecode;
}

export interface UnsignedTx {
  transaction: Transaction;
  sourceOutputs: (Transaction['inputs'][number] & Output)[];
  fee: bigint;
}

/** Rough size of a signed P2PKH transaction (Schnorr or ECDSA signatures, compressed keys). */
export function estimateSize(inputs: number, outputs: Uint8Array[]): number {
  return 10 + inputs * 148 + outputs.reduce((s, o) => s + 9 + o.length + (o.length < 253 ? 1 : 3), 0);
}

/**
 * The commitment transaction: spends `utxos` (all of `address`), one OP_RETURN with the text, change back to the
 * same address. Unsigned: the wallet fills the unlocking bytecode.
 */
export function buildCommitment(address: string, utxos: Utxo[], text: string, feePerByte = 1n): UnsignedTx {
  if (!utxos.length) throw new Error('This address has no coins to pay the fee.');
  const lock = lockingBytecodeOf(address);
  const opReturn = commitmentBytecode(text);
  const total = utxos.reduce((s, u) => s + u.satoshis, 0n);
  const fee = BigInt(estimateSize(utxos.length, [opReturn, lock]) + 2) * feePerByte;
  const change = total - fee;
  if (change < DUST) throw new Error(`Not enough on this address: need about ${fee + DUST} sats, have ${total}.`);
  return assemble(utxos, lock, [{ lockingBytecode: opReturn, valueSatoshis: 0n }, { lockingBytecode: lock, valueSatoshis: change }], fee);
}

/** A plain payment: `amount` to `to`, change to `changeAddress`. `coins` may come from several wallet addresses. */
export function buildPayment(coins: (Utxo & { address: string })[], to: string, amount: bigint, changeAddress: string, feePerByte = 1n): UnsignedTx & { used: (Utxo & { address: string })[] } {
  if (amount < DUST) throw new Error(`Minimum payment is ${DUST} sats.`);
  const toLock = lockingBytecodeOf(to);
  const changeLock = lockingBytecodeOf(changeAddress);
  const sorted = [...coins].sort((a, b) => (b.satoshis > a.satoshis ? 1 : -1));
  const used: (Utxo & { address: string })[] = [];
  let total = 0n;
  for (const c of sorted) {
    used.push(c);
    total += c.satoshis;
    const fee = BigInt(estimateSize(used.length, [toLock, changeLock]) + 2) * feePerByte;
    if (total >= amount + fee) {
      const change = total - amount - fee;
      const outputs: Output[] = [{ lockingBytecode: toLock, valueSatoshis: amount }];
      let finalFee = fee;
      if (change >= DUST) outputs.push({ lockingBytecode: changeLock, valueSatoshis: change });
      else finalFee += change; // dust change goes to the fee
      // each input's own locking bytecode
      const tx = assembleMulti(used, outputs, finalFee);
      return { ...tx, used };
    }
  }
  throw new Error(`Not enough funds: have ${total} sats.`);
}

function assemble(utxos: Utxo[], lock: Uint8Array, outputs: Output[], fee: bigint): UnsignedTx {
  return assembleMulti(utxos.map((u) => ({ ...u, lock })), outputs, fee);
}

function assembleMulti(coins: (Utxo & { lock?: Uint8Array; address?: string })[], outputs: Output[], fee: bigint): UnsignedTx {
  const inputs = coins.map((u) => ({
    outpointTransactionHash: hexToBin(u.txid),
    outpointIndex: u.vout,
    sequenceNumber: 0xffffffff,
    unlockingBytecode: new Uint8Array(),
  }));
  const sourceOutputs = coins.map((u, i) => ({
    ...inputs[i],
    lockingBytecode: u.lock ?? lockingBytecodeOf(u.address!),
    valueSatoshis: u.satoshis,
  }));
  return { transaction: { version: 2, locktime: 0, inputs, outputs }, sourceOutputs, fee };
}

export const txidOf = (hex: string) => binToHex(hashTransactionUiOrder(hexToBin(hex)));
export const encodeTxHex = (tx: Transaction) => binToHex(encodeTransaction(tx));

export type FetchTx = (txid: string) => Promise<string>;
export const fetchFrom = (call: ElectrumCall): FetchTx => (txid) => getTransactionHex(call, txid);

/** Verify an on-chain proof for (address, text). Returns the check to show; never throws. */
export async function verifyTxProof(proof: string, address: string, text: string, fetchTx: FetchTx): Promise<Check> {
  const name = 'On-chain proof: a transaction signed by that address carries the NIP-39 text (the BCH key named this Nostr key)';
  try {
    if (!isTxProof(proof)) return { name, ok: false, detail: 'proof is not tx:<txid>' };
    const txid = proof.slice(TX_PROOF_PREFIX.length);
    const hex = await fetchTx(txid);
    if (txidOf(hex) !== txid) return { name, ok: false, detail: 'server returned a different transaction' };
    const tx = decodeTransaction(hexToBin(hex));
    if (typeof tx === 'string') return { name, ok: false, detail: tx };
    const want = binToHex(commitmentBytecode(text));
    if (!tx.outputs.some((o) => binToHex(o.lockingBytecode) === want)) return { name, ok: false, detail: `transaction ${txid.slice(0, 12)}… does not carry this Nostr key's text` };
    // the coins it spends, each checked against its own txid
    const sourceOutputs = [];
    for (const input of tx.inputs) {
      const prevId = binToHex(input.outpointTransactionHash);
      const prevHex = await fetchTx(prevId);
      if (txidOf(prevHex) !== prevId) return { name, ok: false, detail: 'server returned a different previous transaction' };
      const prev = decodeTransaction(hexToBin(prevHex));
      if (typeof prev === 'string') return { name, ok: false, detail: prev };
      const out = prev.outputs[input.outpointIndex];
      if (!out) return { name, ok: false, detail: 'spent output not found' };
      sourceOutputs.push({ ...input, ...out });
    }
    const lock = binToHex(lockingBytecodeOf(address));
    if (!sourceOutputs.some((s) => binToHex(s.lockingBytecode) === lock)) return { name, ok: false, detail: `no input spends a coin of ${address}` };
    const vm = createVirtualMachineBCH();
    const valid = vm.verify({ transaction: tx, sourceOutputs });
    if (valid !== true) return { name, ok: false, detail: `signature check failed: ${valid}` };
    return { name, ok: true, detail: `tx ${txid}` };
  } catch (e) {
    return { name, ok: false, detail: `could not check: ${(e as Error).message ?? e}` };
  }
}
