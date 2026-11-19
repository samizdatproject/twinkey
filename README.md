# TwinKey

**One identity, two keys you already own.** TwinKey links a Bitcoin Cash address and a Nostr key with two
signatures, each key vouching for the other. The link lives on ordinary Nostr relays as a standard NIP-39 identity
claim. Anyone can find it, any app can verify it, and you can log in with it. No account, no identity server, no
custody.

- **Live demo:** https://samizdatproject.github.io/twinkey/ (link keys, look up anyone, pay an identity)
- **Demo app (log in):** https://samizdatproject.github.io/twinkey/app.html
- **Protocol spec:** [SPEC.md](SPEC.md)
- Built for **BCH BLAZE 2026**, *Decentralized Identity* bounty (Paytaca). New project, all code written during BLAZE (from Nov 19, 2026).

## Try it in one minute

1. Open the demo. Click **Create a demo key** (or **Use my Nostr extension**, e.g. Alby or nos2x).
2. Prove your BCH address, one of three ways:
   - **Link with Paytaca / Selene (WizardConnect):** scan the QR; your wallet approves a tiny transaction from one of
     its addresses carrying the line (OP_RETURN, ~300 sats fee). The proof is that transaction.
   - **Sign with a demo BCH key** (instant, no wallet).
   - **Sign the line in Electron Cash** (*Tools → Sign/Verify Message*) and paste address and signature.
   The page checks the proof before you publish.
3. Click **Publish link**. It goes to public Nostr relays as your NIP-39 list (anything already in it is kept).
4. In **Look up & verify**, enter your npub, a NIP-05 name or the BCH address. Every check is shown, plus a payment
   QR for the verified address and a DID view.
5. Open the **demo app** and log in. It issues a one-time challenge, checks your Nostr signature, finds and verifies
   your BCH link on the relays, and (with step-up) checks a BCH signature over the same nonce.

Demo keys are real keys kept in your browser's local storage. Never send funds to a demo address.

## How it works

```
 BCH key ──signs──▶ "Verifying that I control the following Nostr public key: npub1…"   (Bitcoin Signed Message)
                                         │
 Nostr key ──signs──▶ kind 10011 { tags: [["i", "bch:qq…", "<that signature>"], …] }     (NIP-39 list)
                                         │
                               any Nostr relays (untrusted storage)
                                         │
 Verifier: Nostr signature ✓ · rebuild text from the event author ✓ · recover BCH address from signature ✓
```

1. **Binding.** The BCH key signs NIP-39's own verification text, which names the Nostr key: as a signed message, or
   (for WizardConnect wallets, which cannot sign messages) inside a transaction's OP_RETURN, verified with the BCH VM. The Nostr key signs
   the event that carries the BCH address and that signature. Two different keys (ECDSA and Schnorr), neither
   revealed, each signing for the other. A BCH address merely pasted into a profile would fail.
2. **Discovery.** By Nostr key (`authors`) or by BCH address (`#i` tag filter), on any relays. NIP-05 names work
   too. No database of ours.
3. **Verification.** Pure local cryptography: check the Nostr event signature, rebuild the signed text from the
   event's own author, recover the address from the BCH signature, and use only the author's newest list (so
   unlinking works). A relay can hide a link but cannot forge one.
4. **Login.** NIP-98 challenge-response: a one-time URL with a nonce, a 60-second window, single use. Optional
   step-up: the BCH key signs `Log in to <origin> as <npub> with nonce <n>`, proving both keys are held now.

Full rules, including rotation and unlinking: [SPEC.md](SPEC.md).

## Requirements → where they are

| Bounty requirement | TwinKey |
|---|---|
| 1. Identity creation, user-held keys, no custodian | Nostr: browser extension (NIP-07) or a local demo key. BCH: any wallet that signs messages, or a local demo key. Nothing leaves the user's device except signatures. |
| 2. Cryptographic binding, proofs of control of both, no shared key | BCH signature over the npub + Nostr signature over the address and proof (`src/lib/claim.ts`). |
| 3. Decentralized discovery | Public Nostr relays, by key or by address (`src/lib/relays.ts`). |
| 4. Independent verification + challenge-response auth | `verifyClaims` (browser and Node), CLI, demo app, NIP-98 server example (`src/lib/auth.ts`, `examples/auth-server.ts`). |
| 5. Working demo, source, setup, architecture docs | This repo, the live pages, this README, SPEC.md. |

Stretch goals touched: **identity-based payments** (pay a verified identity by npub/NIP-05: one click with a
WizardConnect wallet, or BIP21 link + QR), **BCH-backed identity commitments** (the on-chain proof: works with
WizardConnect wallets that cannot sign messages, and timestamps the link on chain),
**key rotation and recovery** (SPEC §5: either key can be replaced while the other carries continuity),
**interoperability** (built on NIP-39/NIP-98 and the standard BCH message format, reusable library, CLI, spec, a DID
view with `did:nostr` and `did:pkh`), **privacy** (link a fresh address rather than your main wallet; nothing else is
disclosed). Not attempted: verifiable credentials, portable reputation.

## Run it yourself

```sh
npm install
npm test                  # 38 tests: Electron Cash vectors, Paytaca signer cross-check, forgery cases, relays, login
npm run dev               # the two pages on http://localhost:5173
npm run relay             # optional: in-memory relay on ws://127.0.0.1:7447 (put it in the Relays box)
npm run cli -- verify npub1…            # verify from public relays (or: name@domain, bitcoincash:q…)
npm run cli -- text npub1…              # the line your BCH wallet must sign
npm run cli -- did npub1…               # DID document for a verified link
RELAYS=ws://127.0.0.1:7447 npm run auth-server   # NIP-98 login server on :8788
RELAYS=ws://127.0.0.1:7447 npm run auth-client   # makes an identity, logs in with step-up, shows replay refused
npm run build             # static site in dist/
```

## Code

| Path | What |
|---|---|
| `src/lib/bchmsg.ts` | Bitcoin Signed Message sign/verify/recover, cashaddr normalisation |
| `src/lib/claim.ts` | NIP-39 `bch` claim: build, merge into an existing list, unlink, verify (with a check list) |
| `src/lib/relays.ts` | Relay queries, discovery by key and by address, publish |
| `src/lib/auth.ts` | NIP-98 challenge, verification, replay set, BCH step-up |
| `src/lib/did.ts` | DID view and payment URIs |
| `src/lib/txproof.ts`, `src/lib/electrum.ts` | On-chain proof: build the commitment, verify with the BCH VM over txid-checked data from Electrum servers; payments |
| `src/ui/wizard.ts` | WizardConnect pairing, linking and paying |
| `src/lib/verify-event.ts` | Verifies a clean copy of each event (see Security) |
| `src/ui/` | The two pages |
| `src/cli.ts`, `examples/` | CLI verifier, Node login server and client, dev relay |
| `test/` | Unit and relay tests, with a mock relay and Paytaca's vendored signer for cross-checks |

## Security notes

- **Same format as the sponsor's wallet.** Tests sign with TwinKey and verify with Paytaca's signer (mainnet-js
  `SignedMessage`, vendored from paytaca-app) and vice versa, and verify Electron Cash's published test vectors
  (compressed and uncompressed keys).
- **Found during testing:** nostr-tools caches a successful signature check on the event object, and an object
  spread copies that cache, so `{...verifiedEvent, pubkey: other}` would have passed. Every verifier here checks a
  clean copy; a test covers it.
- **Text rebuilt, never trusted.** The verifier rebuilds the signed text from the event author, so a proof cannot be
  reused for another Nostr key.
- **Newest list only.** Discovery by address re-fetches each author's newest list, so an unlinked claim kept by a
  stale relay does not count.
- **Login.** One-time nonces, exact URL match, 60-second window, nonce marked used only on success.
- **Independent security review** (AI reviewer, Nov 19): no way found to forge a binding. Fixed from it: a few dozen
  spam keys could crowd a real link out of the address lookup (hits are now verified first; a flood larger than the
  200-events-per-relay cap can still hide a link on that relay, lookup by Nostr key is unaffected), non-canonical claim
  spellings could survive an unlink (only the canonical form verifies now), a relay sending other event kinds could
  pollute a merge (filtered), the example server could be crashed by a malformed header (hardened, with TTLs and
  caps), and per-relay/per-list limits. Publishing now shows exactly which `i` tags will be added or removed before
  signing.
- **What a claim proves:** "whoever controls this address named this Nostr key". The signed text is NIP-39's generic
  one (not BCH-specific), so only sign it on a page you trust, for an npub you recognise (SPEC §2).
- **Limits (honest list):** a proof is a permanent statement; if a Nostr key is stolen, the BCH holder recovers by
  linking a new Nostr key (SPEC §5), and a signed revocation is future work. Relays can withhold data: query several.
  The demo app's "server" runs in the page for the static demo; `examples/auth-server.ts` is the same logic as a real
  server. WizardConnect has no sign-message action, hence the on-chain proof for those wallets (it costs the network
  fee and spends from one wallet address, which becomes the linked address).

## How this was built

Written by samizdatproject with Claude Code (Anthropic), which wrote most of the code and tests under review, with
an independent AI security review of the verifier. Disclosed here as for every samizdatproject entry.

## License

MIT. `test/vendor/mainnet-js-signed.js` is from mainnet-js (MIT) via paytaca-app, used only in tests.
