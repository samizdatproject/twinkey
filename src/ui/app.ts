// Page 3: an independent app accepting TwinKey logins. `ShopBackend` is what a real server would run: it only
// sees the signed login event (and optionally a BCH signature) and talks to public relays itself.
import { nip19, type Event } from 'nostr-tools';
import { authTemplate, bchLoginText, newChallenge, verifyAuth, verifyBchStepUp, type Challenge } from '../lib/auth.ts';
import { discoverByPubkey } from '../lib/relays.ts';
import type { Check, ClaimResult } from '../lib/claim.ts';
import { $, copy, demoBch, demoNostrSigner, el, extensionSigner, getRelays, renderChecks, type NostrSigner } from './common.ts';

class ShopBackend {
  private pending = new Map<string, Challenge>();
  private used = new Set<string>();

  issue(): Challenge {
    const c = newChallenge(`${location.origin}${location.pathname.replace(/[^/]*$/, '')}login`);
    this.pending.set(c.nonce, c);
    return c;
  }

  /** Step 1: Nostr login + BCH link lookup. Returns the verified BCH links of this key. */
  async login(event: Event, nonce: string): Promise<{ ok: boolean; checks: Check[]; pubkey?: string; links: ClaimResult[] }> {
    const c = this.pending.get(nonce);
    if (!c) return { ok: false, checks: [{ name: 'Challenge issued by this shop', ok: false }], links: [] };
    const auth = verifyAuth(event, c, { used: this.used });
    if (!auth.ok) return { ok: false, checks: auth.checks, links: [] };
    const { results } = await discoverByPubkey(auth.pubkey!, 'mainnet', getRelays());
    const links = results.filter((r) => r.ok);
    const checks = [...auth.checks, {
      name: 'A valid BCH link for this Nostr key was found on the relays and verified',
      ok: links.length > 0,
      detail: links.length ? links.map((l) => l.address).join(', ') : 'none: link your keys on the TwinKey page first',
    }];
    return { ok: links.length > 0, checks, pubkey: auth.pubkey, links };
  }

  /** Step 2 (optional): the BCH key signs the same nonce. */
  stepUp(nonce: string, pubkey: string, links: ClaimResult[], signature: string): Check {
    const c = this.pending.get(nonce);
    if (!c) return { name: 'BCH key signed this login too', ok: false, detail: 'unknown challenge' };
    for (const l of links) {
      const r = verifyBchStepUp(c, pubkey, l.address!, signature);
      if (r.ok) return r; // detail = the address that signed
    }
    return { name: 'BCH key signed this login too (holds both keys now)', ok: false, detail: 'signature not made by a linked address' };
  }
}

const shop = new ShopBackend();

async function run(get: () => Promise<NostrSigner>) {
  const out = $('#login-out');
  const ch = $('#challenge');
  out.replaceChildren();
  $('#stepup-box').hidden = true;
  $('#session').hidden = true;
  let signer: NostrSigner;
  try { signer = await get(); } catch (e) { ch.textContent = String((e as Error).message ?? e); return; }
  const c = shop.issue();
  ch.replaceChildren(el('p', {}, 'One-time login URL from the shop: ', el('code', {}, c.url)));
  const event = await signer.sign(authTemplate(c));
  out.append(el('p', { class: 'muted' }, 'Signed. The shop is checking the signature and asking the relays for your BCH link…'));
  const res = await shop.login(event, c.nonce);
  out.replaceChildren(renderChecks(res.checks));
  if (!res.ok) { out.append(el('p', { class: 'bad' }, 'Login refused.')); return; }

  if (!$<HTMLInputElement>('#stepup').checked) return showSession(res.pubkey!, res.links, res.checks, false);

  const text = bchLoginText(c, res.pubkey!);
  const demo = demoBch(false);
  if (demo && res.links.some((l) => l.address === demo.address)) {
    const check = shop.stepUp(c.nonce, res.pubkey!, res.links, demo.sign(text));
    return finish(res, check);
  }
  $('#stepup-box').hidden = false;
  $('#stepup-text').textContent = text;
  $('#stepup-copy').onclick = (e) => copy(text, e.currentTarget as HTMLElement);
  $('#stepup-send').onclick = () => finish(res, shop.stepUp(c.nonce, res.pubkey!, res.links, $<HTMLInputElement>('#stepup-sig').value.trim()));
}

function finish(res: { pubkey?: string; links: ClaimResult[]; checks: Check[] }, check: Check) {
  const checks = [...res.checks, check];
  $('#login-out').replaceChildren(renderChecks(checks));
  if (!check.ok) { $('#login-out').append(el('p', { class: 'bad' }, 'Step-up failed: not logged in.')); return; }
  $('#stepup-box').hidden = true;
  showSession(res.pubkey!, res.links, checks, true, check.detail);
}

function showSession(pubkey: string, links: ClaimResult[], _checks: Check[], both: boolean, signedBy?: string) {
  const s = $('#session');
  s.hidden = false;
  s.replaceChildren(
    el('h2', {}, '✓ Welcome back'),
    el('p', {}, 'Signed in as ', el('code', {}, nip19.npubEncode(pubkey))),
    el('p', {}, links.length > 1 ? 'Your verified BCH addresses: ' : 'Your verified BCH address: ', ...links.map((l) => el('code', {}, `${l.address} `))),
    el('p', { class: 'muted' }, both ? `You proved you hold both keys in this session (BCH signature by ${signedBy}).` : 'Logged in with your Nostr key; the BCH link was verified from the relays.'),
    el('p', {}, 'A real shop could pay refunds or rewards to your verified address. No password, no email, no account database. (Demo keys: never send funds to them.)'),
  );
}

$('#login-ext').addEventListener('click', () => run(extensionSigner));
$('#login-demo').addEventListener('click', () => run(async () => {
  const s = demoNostrSigner(false);
  if (!s) throw new Error('No TwinKey demo key in this browser yet. Create one and link it on the TwinKey page first.');
  return s;
}));
