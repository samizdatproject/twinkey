// twinkey CLI: verify a BCH ↔ Nostr link from the command line, straight from public relays.
//   npm run cli -- verify <npub | hex | name@domain | bitcoincash:q…> [--relays wss://a,wss://b]
//   npm run cli -- did <npub | hex>
//   npm run cli -- text <npub | hex>            (the one line your BCH wallet must sign)
import { queryProfile } from 'nostr-tools/nip05';
import { nip19 } from 'nostr-tools';
import { normalizeAddress } from './lib/bchmsg.ts';
import { toPubkeyHex, verificationText, type ClaimResult } from './lib/claim.ts';
import { DEFAULT_RELAYS, discoverByAddress, discoverByPubkey } from './lib/relays.ts';
import { didDocument } from './lib/did.ts';

const [cmd, arg, ...rest] = process.argv.slice(2);
const flag = rest.indexOf('--relays');
const relays = flag >= 0 ? rest[flag + 1].split(',') : DEFAULT_RELAYS;

async function pubkeyOf(s: string): Promise<string> {
  const hex = toPubkeyHex(s) ?? (s.includes('@') ? (await queryProfile(s))?.pubkey : undefined);
  if (!hex) throw new Error(`not a Nostr key or NIP-05 name: ${s}`);
  return hex;
}

function print(r: ClaimResult) {
  console.log(`\n${r.ok ? 'VALID' : 'INVALID'}  ${r.npub}  ↔  ${r.address ?? '(no address)'}`);
  for (const c of r.checks) console.log(`  ${c.ok ? '✓' : '✗'} ${c.name}${c.detail ? ` — ${c.detail}` : ''}`);
}

async function main() {
  if (!cmd || !arg) {
    console.log('usage: twinkey verify <npub|hex|name@domain|bitcoincash:q…> [--relays a,b] | did <npub> | text <npub>');
    process.exit(2);
  }
  if (cmd === 'text') { console.log(verificationText(await pubkeyOf(arg))); return; }
  if (cmd === 'did') {
    const { results } = await discoverByPubkey(await pubkeyOf(arg), 'mainnet', relays);
    const ok = results.find((r) => r.ok);
    if (!ok) { console.error('no valid BCH link found'); process.exit(1); }
    console.log(JSON.stringify(didDocument(ok.pubkey, ok.address!), null, 2));
    return;
  }
  if (cmd === 'verify') {
    const addr = normalizeAddress(arg);
    const results = addr ? await discoverByAddress(addr, 'mainnet', relays) : (await discoverByPubkey(await pubkeyOf(arg), 'mainnet', relays)).results;
    if (!results.length) { console.log(`no link found on ${relays.join(', ')}`); process.exit(1); }
    results.forEach(print);
    process.exit(results.some((r) => r.ok) ? 0 : 1);
  }
  console.error(`unknown command ${cmd}`);
  process.exit(2);
}
main().catch((e) => { console.error(e?.message ?? e); process.exit(1); });
void nip19;
