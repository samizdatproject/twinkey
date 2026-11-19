// Minimal Electrum-protocol client (Fulcrum servers over WSS), with failover across independent public servers.
// Used to fetch transactions for on-chain proofs and UTXOs for WizardConnect transactions. Servers are untrusted:
// every transaction fetched is re-hashed against its txid, and proofs are checked with the BCH VM locally.
export const DEFAULT_ELECTRUM = [
  'wss://bch.imaginary.cash:50004', 'wss://electrum.imaginary.cash:50004', 'wss://blackie.c3-soft.com:50004',
  'wss://fulcrum.greyh.at:50004', 'wss://bch.soul-dev.com:50004', 'wss://fulcrum.criptolayer.net:50004', 'wss://bch.loping.net:50004',
];

export type ElectrumCall = (method: string, params: unknown[]) => Promise<any>;

function callOnce(url: string, method: string, params: unknown[], timeoutMs: number): Promise<any> {
  return new Promise((resolve, reject) => {
    let ws: WebSocket;
    const timer = setTimeout(() => { try { ws.close(); } catch { /* */ } reject(new Error(`${url}: timeout`)); }, timeoutMs);
    try { ws = new WebSocket(url); } catch (e) { clearTimeout(timer); reject(e); return; }
    ws.onopen = () => ws.send(JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }));
    ws.onmessage = (m) => {
      clearTimeout(timer);
      try { ws.close(); } catch { /* */ }
      try {
        const d = JSON.parse(String(m.data));
        if (d.error) reject(new Error(`${url}: ${d.error.message ?? JSON.stringify(d.error)}`));
        else resolve(d.result);
      } catch (e) { reject(e); }
    };
    ws.onerror = () => { clearTimeout(timer); reject(new Error(`${url}: connection failed`)); };
  });
}

/** An Electrum caller that tries servers in a random order until one answers. */
export function electrum(servers = DEFAULT_ELECTRUM, timeoutMs = 10_000): ElectrumCall {
  return async (method, params) => {
    const order = [...servers].sort(() => Math.random() - 0.5);
    let last: unknown;
    for (const url of order) {
      try { return await callOnce(url, method, params, timeoutMs); } catch (e) { last = e; }
    }
    throw last instanceof Error ? last : new Error('no Electrum server answered');
  };
}

export interface Utxo { txid: string; vout: number; satoshis: bigint; height: number }

export async function listUnspent(call: ElectrumCall, address: string): Promise<Utxo[]> {
  const r = (await call('blockchain.address.listunspent', [address])) as { tx_hash: string; tx_pos: number; value: number; height: number; token_data?: unknown }[];
  // token UTXOs are left alone: spending them in a plain transaction could burn tokens
  return r.filter((u) => !u.token_data).map((u) => ({ txid: u.tx_hash, vout: u.tx_pos, satoshis: BigInt(u.value), height: u.height }));
}

export const getTransactionHex = (call: ElectrumCall, txid: string): Promise<string> => call('blockchain.transaction.get', [txid, false]);
export const broadcast = (call: ElectrumCall, hex: string): Promise<string> => call('blockchain.transaction.broadcast', [hex]);
