// WizardConnect (Paytaca, Selene, Cashonize): pair by QR or link, read the wallet's addresses from its xpubs, and
// ask it to sign transactions. Used for the on-chain link proof and for "pay this identity".
import { initiateDappRelay, type DappRelayResult } from '@wizardconnect/core';
import { DappConnectionManager } from '@wizardconnect/dapp';
import { encodeCashAddress, hash160 } from '@bitauth/libauth';
import { broadcast, electrum, listUnspent, type ElectrumCall, type Utxo } from '../lib/electrum.ts';
import { buildCommitment, buildPayment, txidOf, type UnsignedTx } from '../lib/txproof.ts';

const PATH = { 0: 'receive', 1: 'change' } as const;
type Child = 0 | 1;
interface Coin extends Utxo { address: string; child: Child; index: number }

export class Wizard {
  readonly call: ElectrumCall = electrum();
  private constructor(private mgr: DappConnectionManager, private relay: DappRelayResult) {}

  /** Start pairing; `show` gets the QR payload and the wallet link. Resolves once the wallet is ready. */
  static connect(show: (qrUri: string, uri: string) => void, timeoutMs = 180_000): Promise<Wizard> {
    return new Promise((resolve, reject) => {
      const mgr = new DappConnectionManager('TwinKey', undefined, { session: false });
      const relay = initiateDappRelay(({ client, status }) => mgr.updateConnection(client, status));
      mgr.attachRelay(relay);
      const timer = setTimeout(() => { relay.cleanup(); reject(new Error('The wallet did not connect in time.')); }, timeoutMs);
      mgr.once('walletready', () => { clearTimeout(timer); resolve(new Wizard(mgr, relay)); });
      mgr.once('disconnect', (_r, m) => { clearTimeout(timer); reject(new Error(`Wallet disconnected${m ? `: ${m}` : ''}`)); });
      show(relay.qrUri, relay.uri);
    });
  }

  get walletName() { return this.mgr.walletName ?? 'wallet'; }

  address(child: Child, index: number): string {
    const pub = this.mgr.getPubkey(child, BigInt(index));
    if (!pub) throw new Error('The wallet did not share this address path.');
    return encodeCashAddress({ prefix: 'bitcoincash', type: 'p2pkh', payload: hash160(pub) }).address;
  }

  /** Plain (non-token) coins on the first receive and change addresses. */
  async coins(receive = 10, change = 5): Promise<Coin[]> {
    const slots: [Child, number][] = [...Array.from({ length: receive }, (_, i) => [0, i] as [Child, number]), ...Array.from({ length: change }, (_, i) => [1, i] as [Child, number])];
    const found = await Promise.all(slots.map(async ([child, index]) => {
      const address = this.address(child, index);
      try { return (await listUnspent(this.call, address)).map((u) => ({ ...u, address, child, index })); } catch { return []; }
    }));
    return found.flat();
  }

  private async signAndSend(u: UnsignedTx, coins: Coin[], userPrompt: string): Promise<string> {
    const inputPaths = coins.map((c, i) => [i, PATH[c.child], c.index] as [number, string, number]);
    const res = await this.mgr.signTransaction({
      transaction: { transaction: u.transaction, sourceOutputs: u.sourceOutputs, broadcast: true, userPrompt },
      inputPaths,
    });
    if (res.error || !res.signedTransaction) throw new Error(res.error || 'The wallet did not sign.');
    const hex = res.signedTransaction;
    // the wallet broadcasts too; sending it again is harmless and covers wallets that don't
    await broadcast(this.call, hex).catch((e) => {
      if (!/already|known|txn-mempool-conflict|missing/i.test(String(e?.message ?? e))) throw e;
    });
    return txidOf(hex);
  }

  /** Link: the wallet spends a coin of one of its addresses in a transaction carrying `text`. */
  async link(text: string): Promise<{ address: string; txid: string }> {
    const coins = await this.coins();
    if (!coins.length) throw new Error('No coins found in the wallet\'s first addresses. Send it a few thousand sats first.');
    // the address with the most money becomes the linked address; spend at most its 3 largest coins
    const byAddr = new Map<string, Coin[]>();
    for (const c of coins) byAddr.set(c.address, [...(byAddr.get(c.address) ?? []), c]);
    const [address, own] = [...byAddr.entries()].sort((a, b) => Number(sum(b[1]) - sum(a[1])))[0];
    const use = own.sort((a, b) => (b.satoshis > a.satoshis ? 1 : -1)).slice(0, 3);
    const u = buildCommitment(address, use, text);
    const txid = await this.signAndSend(u, use, 'TwinKey: link this address to your Nostr key (OP_RETURN, fee only)');
    return { address, txid };
  }

  /** Pay `amount` sats to `to`, change to the wallet's first change address. */
  async pay(to: string, amount: bigint): Promise<string> {
    const coins = await this.coins();
    const p = buildPayment(coins, to, amount, this.address(1, 0));
    const used = p.used as Coin[];
    return this.signAndSend(p, used, `TwinKey: pay ${amount} sats to a verified identity`);
  }

  disconnect() { this.mgr.sendDisconnect().catch(() => {}); this.relay.cleanup(); }
}

const sum = (cs: Coin[]) => cs.reduce((s, c) => s + c.satoshis, 0n);
