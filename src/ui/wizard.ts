// WizardConnect (Paytaca, Selene, Cashonize): pair by QR or link, read the wallet's addresses from its xpubs, and
// ask it to sign transactions. Used for the on-chain link proof and for "pay this identity".
import { initiateDappRelay, type DappRelayResult } from '@wizardconnect/core';
import { DappConnectionManager } from '@wizardconnect/dapp';
import { wizardSignRequest } from '../lib/wcrequest.ts';
import { encodeCashAddress, hash160 } from '@bitauth/libauth';
import { broadcast, electrum, listUnspent, type ElectrumCall, type Utxo } from '../lib/electrum.ts';
import { binToHex, decodeTransaction, hexToBin } from '@bitauth/libauth';
import { getTransactionHex } from '../lib/electrum.ts';
import { buildCommitment, buildPayment, commitmentBytecode, txidOf, type UnsignedTx } from '../lib/txproof.ts';

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

  /**
   * Plain (non-token) coins of the wallet. Standard gap-limit scan: walk each chain (receive, change) in batches
   * until 20 addresses in a row have never been used; busy wallets (Paytaca) keep money at high address indexes.
   */
  async coins(gap = 20, max = 400): Promise<Coin[]> {
    const out: Coin[] = [];
    for (const child of [0, 1] as Child[]) {
      let lastUsed = -1;
      for (let start = 0; start < max && start <= lastUsed + gap; start += gap) {
        const batch = Array.from({ length: gap }, (_, k) => start + k);
        const res = await Promise.all(batch.map(async (index) => {
          const address = this.address(child, index);
          try {
            const hist = (await this.call('blockchain.address.get_history', [address])) as unknown[];
            if (!hist.length) return { index, used: false, coins: [] as Coin[] };
            const utxos = await listUnspent(this.call, address);
            return { index, used: true, coins: utxos.map((u) => ({ ...u, address, child, index })) };
          } catch { return { index, used: false, coins: [] as Coin[] }; }
        }));
        for (const r of res) { if (r.used) lastUsed = Math.max(lastUsed, r.index); out.push(...r.coins); }
      }
    }
    return out;
  }

  private async signAndSend(u: UnsignedTx, coins: Coin[], userPrompt: string): Promise<string> {
    const inputPaths = coins.map((c, i) => [i, PATH[c.child], c.index] as [number, string, number]);
    const res = await this.mgr.signTransaction({
      transaction: wizardSignRequest(u, userPrompt) as never, // relay-safe encoding (see wcrequest.ts)
      inputPaths,
    }, { signal: AbortSignal.timeout(180_000) }); // a request nobody answers is cancelled in the wallet too
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
    if (!coins.length) throw new Error('No spendable BCH found in this wallet (token coins are skipped). Send it a few thousand sats first.');
    // the address with the most money becomes the linked address; spend at most its 3 largest coins
    const byAddr = new Map<string, Coin[]>();
    for (const c of coins) byAddr.set(c.address, [...(byAddr.get(c.address) ?? []), c]);
    const [address, own] = [...byAddr.entries()].sort((a, b) => Number(sum(b[1]) - sum(a[1])))[0];
    const use = own.sort((a, b) => (b.satoshis > a.satoshis ? 1 : -1)).slice(0, 3);
    const u = buildCommitment(address, use, text);
    // Wallets broadcast the transaction themselves; if their reply to the page is lost, the chain still shows it.
    // So race the wallet's answer against a watcher looking for the commitment on this address.
    const stop = new AbortController();
    const seen = new Set(((await this.call('blockchain.address.get_history', [address]).catch(() => [])) as { tx_hash: string }[]).map((h) => h.tx_hash));
    const fromWallet = this.signAndSend(u, use, 'TwinKey: link this address to your Nostr key (OP_RETURN, fee only)');
    const fromChain = this.watchCommitment(address, text, seen, stop.signal);
    try {
      const txid = await Promise.any([fromWallet, fromChain]);
      return { address, txid };
    } catch (e) {
      throw (e as AggregateError).errors?.[0] ?? e;
    } finally {
      stop.abort();
    }
  }

  /** Poll the address history for a new transaction carrying `text` in an OP_RETURN. */
  private async watchCommitment(address: string, text: string, seen: Set<string>, signal: AbortSignal): Promise<string> {
    const want = binToHex(commitmentBytecode(text));
    const deadline = Date.now() + 180_000;
    while (!signal.aborted && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 4000));
      try {
        const hist = (await this.call('blockchain.address.get_history', [address])) as { tx_hash: string }[];
        for (const h of hist) {
          if (seen.has(h.tx_hash)) continue;
          seen.add(h.tx_hash);
          const hex = await getTransactionHex(this.call, h.tx_hash);
          const tx = decodeTransaction(hexToBin(hex));
          if (typeof tx !== 'string' && txidOf(hex) === h.tx_hash && tx.outputs.some((o) => binToHex(o.lockingBytecode) === want)) return h.tx_hash;
        }
      } catch { /* keep polling */ }
    }
    throw new Error('No linking transaction seen on the network.');
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
