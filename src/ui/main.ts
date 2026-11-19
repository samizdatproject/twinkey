// Page 1: create the link (publish) and look up / verify anyone (discover).
import qrcode from 'qrcode-generator';
import { nip19 } from 'nostr-tools';
import { normalizeAddress, recoverAddress } from '../lib/bchmsg.ts';
import { claimTag, identityTemplate, mergeClaim, removeClaim, verificationText, type ClaimResult } from '../lib/claim.ts';
import { defaultFetchTx, discoverByAddress, discoverByPubkey, fetchIdentityList, publish } from '../lib/relays.ts';
import { isTxProof, verifyTxProof } from '../lib/txproof.ts';
import { Wizard } from './wizard.ts';
import { didDocument, paymentUri } from '../lib/did.ts';
import {
  $, copy, demoBch, demoNostrSigner, el, extensionSigner, forgetDemoKeys, getRelays, renderChecks, resolvePubkey, setRelays, short,
  type NostrSigner,
} from './common.ts';

let signer: NostrSigner | undefined;
let wizard: Wizard | undefined;
/** On-chain proofs are checked online; the result is cached per (npub, address, proof). */
const txChecked = new Map<string, boolean | 'checking'>();

async function getWizard(status: (s: string) => void): Promise<Wizard> {
  if (wizard) return wizard;
  const box = $('#wizard-box');
  box.hidden = false;
  status('Scan with Paytaca or Selene (WizardConnect), or open your wallet on this phone…');
  wizard = await Wizard.connect((qrUri, uri) => {
    const qr = qrcode(0, 'L');
    qr.addData(qrUri);
    qr.make();
    $('#wizard-qr').innerHTML = qr.createSvgTag({ cellSize: 3, margin: 2, scalable: true }); // SVG generated locally
    $<HTMLAnchorElement>('#wizard-link').href = uri;
  });
  $('#wizard-qr').replaceChildren();
  $<HTMLAnchorElement>('#wizard-link').parentElement!.hidden = true;
  status(`Connected to ${wizard.walletName}.`);
  return wizard;
}

const addrIn = $<HTMLInputElement>('#bch-address');
const sigIn = $<HTMLInputElement>('#bch-sig');
const relaysIn = $<HTMLTextAreaElement>('#relays');
relaysIn.value = getRelays().join('\n');
relaysIn.addEventListener('change', () => setRelays(relaysIn.value));

function setSigner(s: NostrSigner) {
  signer = s;
  $('#nostr-who').textContent = `${s.kind === 'demo' ? 'Demo key' : 'Extension key'}: ${nip19.npubEncode(s.pubkey)}`;
  $('#text-to-sign').textContent = verificationText(s.pubkey);
  refresh();
}

$('#nostr-ext').addEventListener('click', async () => {
  try { setSigner(await extensionSigner()); } catch (e) { $('#nostr-who').textContent = String((e as Error).message ?? e); }
});
$('#nostr-demo').addEventListener('click', () => setSigner(demoNostrSigner()!));
$('#forget').addEventListener('click', () => {
  if (!window.confirm('Delete the demo Nostr and BCH keys stored in this browser? (Unlink first if you published a link.)')) return;
  forgetDemoKeys();
  signer = undefined;
  addrIn.value = '';
  sigIn.value = '';
  $('#nostr-who').textContent = 'Demo keys deleted.';
  $('#text-to-sign').textContent = 'Choose a Nostr key first.';
  refresh();
});
$('#copy-text').addEventListener('click', (e) => signer && copy(verificationText(signer.pubkey), e.currentTarget as HTMLElement));
$('#bch-demo').addEventListener('click', () => {
  if (!signer) { $('#sig-status').textContent = 'Choose a Nostr key first.'; return; }
  const w = demoBch()!;
  addrIn.value = w.address;
  sigIn.value = w.sign(verificationText(signer.pubkey));
  refresh();
});
$('#bch-wizard').addEventListener('click', async () => {
  if (!signer) { $('#sig-status').textContent = 'Choose a Nostr key first.'; return; }
  const st = $('#wizard-status');
  const status = (s: string) => { st.textContent = s; };
  try {
    const w = await getWizard(status);
    status(`Looking for coins in ${w.walletName}…`);
    const text = verificationText(signer.pubkey);
    status('Approve the transaction in your wallet (it only pays the network fee)…');
    const { address, txid } = await w.link(text);
    addrIn.value = address;
    sigIn.value = `tx:${txid}`;
    txChecked.set(`${signer.pubkey}|${address}|tx:${txid}`, true);
    status(`✓ Sent: transaction ${short(txid, 8)} links ${address}. Now publish below.`);
    refresh();
  } catch (e) {
    status(`✗ ${(e as Error).message ?? e}`);
    if (/connect|disconnect/i.test(String((e as Error).message))) wizard = undefined;
  }
});
addrIn.addEventListener('input', refresh);
sigIn.addEventListener('input', refresh);

/** Live check of the pasted signature, before anything is published. */
function currentClaim(): string[] | undefined {
  const status = $('#sig-status');
  status.className = 'status';
  if (!signer) { status.textContent = ''; return undefined; }
  const address = normalizeAddress(addrIn.value);
  if (!addrIn.value.trim()) { status.textContent = ''; return undefined; }
  if (!address) { status.textContent = 'Not a Bitcoin Cash P2PKH address (bitcoincash:q… or z…).'; status.classList.add('bad'); return undefined; }
  if (!sigIn.value.trim()) { status.textContent = 'Paste the signature from your wallet.'; return undefined; }
  const proof = sigIn.value.trim();
  if (proof.startsWith('tx:')) {
    if (!isTxProof(proof)) { status.textContent = 'An on-chain proof looks like tx:<64 hex characters>.'; status.classList.add('bad'); return undefined; }
    const key = `${signer.pubkey}|${address}|${proof}`;
    const state = txChecked.get(key);
    if (state === true) { status.textContent = `✓ On-chain proof valid: ${address} signed a transaction naming your Nostr key.`; status.classList.add('ok'); return claimTag(address, proof); }
    if (state === false) { status.textContent = 'That transaction does not prove this address named your Nostr key.'; status.classList.add('bad'); return undefined; }
    if (state === undefined) {
      txChecked.set(key, 'checking');
      verifyTxProof(proof, address, verificationText(signer.pubkey), defaultFetchTx).then((c) => { txChecked.set(key, c.ok); refresh(); });
    }
    status.textContent = 'Checking the transaction on the BCH network…';
    return undefined;
  }
  const signer_ = recoverAddress(verificationText(signer.pubkey), sigIn.value);
  if (signer_ !== address) {
    status.textContent = signer_ ? `This signature was made by ${signer_}, not ${address}.` : 'This is not a valid Bitcoin signed message signature.';
    status.classList.add('bad');
    return undefined;
  }
  status.textContent = `✓ Signature valid: ${address} signed your Nostr key.`;
  status.classList.add('ok');
  return claimTag(address, sigIn.value);
}

function refresh() {
  const tag = currentClaim();
  $<HTMLButtonElement>('#publish').disabled = !tag;
  $<HTMLButtonElement>('#unlink').disabled = !signer || !normalizeAddress(addrIn.value);
  $('#preview').textContent = tag && signer
    ? JSON.stringify({ kind: 10011, pubkey: signer.pubkey, tags: [tag], content: '' }, null, 2)
    : '';
}

async function publishTags(build: (existing: Awaited<ReturnType<typeof fetchIdentityList>>) => string[][], verb: string) {
  if (!signer) return;
  const out = $('#publish-status');
  const relays = getRelays();
  out.replaceChildren(el('p', {}, 'Fetching your current identity list (so nothing in it is lost)…'));
  try {
    const existing = await fetchIdentityList(signer.pubkey, relays);
    const tags = build(existing);
    const key = (t: string[]) => `${t[0]} ${t[1]}`;
    const before = new Set((existing?.tags ?? []).filter((t) => t[0] === 'i').map(key));
    const after = new Set(tags.filter((t) => t[0] === 'i').map(key));
    const added = [...after].filter((k) => !before.has(k));
    const removed = [...before].filter((k) => !after.has(k));
    const kept = [...after].filter((k) => before.has(k));
    const summary = [`Your identity list will be replaced with:`, ...added.map((k) => `  + ${k}`), ...removed.map((k) => `  − ${k}`),
      ...kept.map((k) => `  = ${k}`), existing ? '' : '(no earlier list found on these relays)', 'Sign and publish?'].join('\n');
    if (!window.confirm(summary)) { out.append(el('p', { class: 'muted' }, 'Cancelled.')); return; }
    const ev = await signer.sign(identityTemplate(tags, existing));
    out.append(el('p', {}, `Signed event ${short(ev.id, 8)}. Sending to ${relays.length} relays…`));
    const res = await publish(ev, relays);
    out.append(
      el('p', { class: res.accepted.length ? 'ok' : 'bad' }, res.accepted.length ? `✓ ${verb} on ${res.accepted.length} relay(s): ${res.accepted.join(', ')}` : `No relay accepted it.`),
      ...res.errors.map((e) => el('p', { class: 'muted' }, e)),
    );
    if (res.accepted.length) {
      const q = $<HTMLInputElement>('#q');
      q.value = nip19.npubEncode(signer.pubkey);
      out.append(el('p', {}, el('a', { href: '#lookup', onclick: () => lookup() }, 'Verify it from the relays now →')));
    }
  } catch (e) {
    out.append(el('p', { class: 'bad' }, `Failed: ${(e as Error).message ?? e}`));
  }
}

$('#publish').addEventListener('click', () => {
  const tag = currentClaim();
  if (tag) publishTags((existing) => mergeClaim(existing, tag), 'Published');
});
$('#unlink').addEventListener('click', () => {
  const a = normalizeAddress(addrIn.value);
  if (a) publishTags((existing) => removeClaim(existing, a), 'Unlinked');
});

// ---- look up and verify
function renderResult(r: ClaimResult): HTMLElement {
  const card = el('div', { class: `result ${r.ok ? 'ok' : 'bad'}` },
    el('h3', {}, r.ok ? '✓ Verified link' : r.address === undefined && r.checks.some((c) => c.name === 'Contains a bch claim')
      ? 'No BCH address linked (never linked, or unlinked)' : '✗ Not a valid link'),
    el('p', {}, el('b', {}, 'Nostr: '), el('code', {}, r.npub)),
    r.address ? el('p', {}, el('b', {}, 'BCH: '), el('code', {}, r.address)) : null,
    r.createdAt ? el('p', { class: 'muted' }, `Published ${new Date(r.createdAt * 1000).toLocaleString()} · event ${short(r.eventId ?? '', 8)} · proof: ${r.proofType === 'tx' ? 'on-chain transaction' : 'signed message'}`) : null,
    renderChecks(r.checks));
  if (r.ok && r.address) {
    const address = r.address;
    const amount = el('input', { type: 'number', min: '0', step: '0.0001', placeholder: 'amount (BCH)', class: 'amount' });
    const qrBox = el('div', { class: 'qr' });
    const link = el('a', { class: 'paylink' });
    const draw = () => {
      const uri = paymentUri(address, Number(amount.value) || undefined);
      link.href = uri;
      link.textContent = `Open in wallet: ${short(uri, 18)}`;
      const qr = qrcode(0, 'M');
      qr.addData(uri);
      qr.make();
      qrBox.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 2, scalable: true }); // SVG generated locally from the URI
    };
    amount.addEventListener('input', draw);
    draw();
    const payStatus = el('p', { class: 'status' });
    const payBtn = el('button', { class: 'small', onclick: async () => {
      const bch = Number(amount.value);
      if (!(bch > 0)) { payStatus.textContent = 'Enter an amount first.'; return; }
      const sats = BigInt(Math.round(bch * 1e8));
      try {
        const w = await getWizard((s) => { payStatus.textContent = s; });
        payStatus.textContent = 'Approve the payment in your wallet…';
        const txid = await w.pay(address, sats);
        payStatus.replaceChildren('✓ Paid: ', el('a', { href: `https://blockchair.com/bitcoin-cash/transaction/${txid}`, target: '_blank', rel: 'noopener' }, short(txid, 10)));
      } catch (e) { payStatus.textContent = `✗ ${(e as Error).message ?? e}`; }
    } }, 'Pay with WizardConnect');
    card.append(
      el('div', { class: 'pay' }, el('h4', {}, 'Pay this identity'),
        el('p', { class: 'muted' }, 'The address comes from the verified link, not from anything the payee typed.'),
        el('div', { class: 'row' }, amount, payBtn, link), payStatus, qrBox),
      el('details', {}, el('summary', {}, 'DID document (did:nostr + did:pkh)'),
        el('pre', { class: 'preview' }, JSON.stringify(didDocument(r.pubkey, address), null, 2))),
    );
  }
  return card;
}

async function lookup() {
  const input = $<HTMLInputElement>('#q').value.trim();
  const out = $('#lookup-out');
  if (!input) return;
  out.replaceChildren(el('p', { class: 'muted' }, `Asking ${getRelays().length} relays…`));
  try {
    const addr = normalizeAddress(input);
    if (addr) {
      const results = await discoverByAddress(addr, 'mainnet', getRelays());
      out.replaceChildren(results.length
        ? el('div', {}, el('p', {}, `${results.filter((r) => r.ok).length} Nostr key(s) validly linked to ${addr}:`), ...results.map(renderResult))
        : el('p', {}, `No Nostr key on these relays links ${addr}.`));
      return;
    }
    const pubkey = await resolvePubkey(input);
    if (!pubkey) { out.replaceChildren(el('p', { class: 'bad' }, 'Not an npub, hex key, NIP-05 name or BCH address.')); return; }
    const { list, results } = await discoverByPubkey(pubkey, 'mainnet', getRelays());
    out.replaceChildren(!list
      ? el('p', {}, `${nip19.npubEncode(pubkey)} has no NIP-39 identity list on these relays.`)
      : el('div', {}, ...results.map(renderResult)));
  } catch (e) {
    out.replaceChildren(el('p', { class: 'bad' }, `Lookup failed: ${(e as Error).message ?? e}`));
  }
}
$('#lookup-btn').addEventListener('click', lookup);
$<HTMLInputElement>('#q').addEventListener('keydown', (e) => { if (e.key === 'Enter') lookup(); });

// resume a demo session
const existingDemo = demoNostrSigner(false);
if (existingDemo) setSigner(existingDemo);
const params = new URLSearchParams(location.search);
const q0 = params.get('q');
if (q0) {
  $<HTMLInputElement>('#q').value = q0;
  if (!q0.includes('@')) lookup(); // a NIP-05 name from a link is only looked up when the user clicks
}
