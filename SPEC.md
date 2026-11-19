# TwinKey protocol: a `bch` claim type for NIP-39

Status: proposal, version 1. Built on [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md),
[NIP-39](https://github.com/nostr-protocol/nips/blob/master/39.md) (external identities, kind `10011`) and
[NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md) (HTTP auth). Nothing new on the BCH side:
signatures use the Bitcoin Signed Message format that Electron Cash, mainnet-js and Paytaca already produce.

## 1. Claim

A Nostr user who controls the Bitcoin Cash P2PKH address `A` adds this tag to their NIP-39 list (kind `10011`):

```json
["i", "bch:<A without the bitcoincash: prefix, lowercase, q… form>", "<proof>"]
```

- **Platform** `bch` = Bitcoin Cash mainnet (`bchtest` for chipnet/testnet).
- **Identity** = the cashaddr payload of the P2PKH address, lowercase, without prefix. A token-aware `z…` address is
  written in its `q…` form (same key hash). P2SH addresses cannot be claimed: a message signature proves a key.
- **Proof** = base64 Bitcoin Signed Message signature by the key of `A` over the exact NIP-39 verification text:

  ```
  Verifying that I control the following Nostr public key: <npub of the event author>
  ```

  One ASCII line, no trailing newline. Message hash: `sha256(sha256("\x18Bitcoin Signed Message:\n" ‖
  compactSize(len) ‖ utf8(text)))`. Signature: `header ‖ r ‖ s` (65 bytes), header `27 + recid` for an uncompressed
  key, `31 + recid` for a compressed key.

The list is a replaceable event: publishers MUST fetch their current kind `10011` and keep its other tags (other
platforms, other addresses), and MUST give the new event a `created_at` greater than the one it replaces.

## 2. Verification

Given a kind `10011` event `E` (from any relay, any cache, any file):

1. `E.kind == 10011` and `E` has a valid NIP-01 id and BIP-340 signature. Verify a clean copy of the event (some
   libraries cache a successful check on the object).
2. For each tag `["i", "bch:<id>", <proof>]`: decode `bitcoincash:<id>`; it MUST be a P2PKH cashaddr.
3. Rebuild the text from **`E.pubkey`** (never from a string supplied with the claim):
   `Verifying that I control the following Nostr public key: ` + `npub(E.pubkey)`.
4. Recover the public key from `proof` over that text (compressed if header ≥ 31), hash160 it, encode as P2PKH
   cashaddr. It MUST equal the claimed address.

If all hold, the BCH key holder named this Nostr key, and this Nostr key published this address: the binding is
valid. A claim copied into another user's list fails step 3–4; an edited event fails step 1.

**Which event counts.** Only the author's newest kind `10011` (highest `created_at`, ties broken by lowest id, as
NIP-01). A verifier that found an event through a `#i` search MUST fetch the author's newest list and require the
claim to be in it, because unlinking is done by publishing a newer list without the claim.

## 3. Discovery

- By Nostr key: `{"kinds":[10011],"authors":[<hex>]}`.
- By BCH address: `{"kinds":[10011],"#i":["bch:<id>"]}` (relays index single-letter tags), then the newest list of
  each author found.
- NIP-05 (`name@domain`) can be used to find the Nostr key first.

Relays are untrusted storage. A relay can withhold an event (query several), but cannot forge one.

## 4. Authentication (login)

Standard NIP-98:

1. The app issues a one-time URL with a random nonce (`…/login?nonce=<32 hex>`), valid for a short time, usable once.
2. The user's Nostr key signs a kind `27235` event with tags `["u", <that URL>]` and `["method", "POST"]`.
3. The app checks: signature, `u` equals the issued URL exactly, `method`, `created_at` within 60 s, challenge not
   expired, nonce unused (then marks it used). Then it discovers and verifies the user's `bch` claim (§2–3).

Optional **step-up** (proves the user holds both keys now, not just when the link was made): the BCH key signs

```
Log in to <app origin> as <npub> with nonce <nonce>
```

and the app checks it recovers to one of the user's verified addresses.

## 5. Rotation, recovery, revocation

- **New BCH address**: sign the text with the new key and publish the list with the new claim (and without the old
  one if it should no longer be linked). The Nostr identity carries the continuity.
- **New Nostr key** (lost or compromised): the BCH key signs the text for the new npub; the new key publishes the
  claim. Anyone can see the same BCH address vouching for the new key, which is the continuity proof. Clients that
  show both should prefer the newest claim and may warn.
- **Unlink**: publish a newer list without the claim.
- **Limit (v1)**: a proof is a permanent statement. If the *Nostr* key is stolen, the thief can keep republishing an
  old claim; the BCH holder's defence is to link a new Nostr key (above). A signed revocation statement from the BCH
  key is a natural v2 addition.

## 6. Interop

- DID view: `did:nostr:<hex>` with `alsoKnownAs` `did:pkh:bip122:000000000000000000651ef99cb9fcbe:<cashaddr>`
  (CAIP-2 chain id of Bitcoin Cash).
- Payments: a wallet resolving a Nostr user to a BCH address SHOULD use only an address from a verified claim
  (BIP21 `bitcoincash:<address>?amount=…`).
- Wallet support needed: "sign message" with a P2PKH key (Electron Cash, Paytaca's signer, mainnet-js). WalletConnect
  `bch_signMessage` can produce the proof without copy-paste.
