# TwinKey protocol: a `bch` claim type for NIP-39

Status: proposal, version 1. Built on [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md),
[NIP-39](https://github.com/nostr-protocol/nips/blob/master/39.md) (external identities, kind `10011`) and
[NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md) (HTTP auth). Nothing new on the BCH side:
signatures use the Bitcoin Signed Message format of Electron Cash's *Sign Message*, mainnet-js, and the signer inside
the Paytaca app (which Paytaca exposes to dapps through WalletConnect).

## 1. Claim

A Nostr user who controls the Bitcoin Cash P2PKH address `A` adds this tag to their NIP-39 list (kind `10011`):

```json
["i", "bch:<A without the bitcoincash: prefix, lowercase, q… form>", "<proof>"]
```

- **Platform** `bch` = Bitcoin Cash mainnet (`bchtest` for chipnet/testnet).
- **Identity** = the cashaddr payload of the P2PKH address, lowercase, without prefix. A token-aware `z…` address is
  written in its `q…` form (same key hash). P2SH addresses cannot be claimed: a message signature proves a key.
  Verifiers MUST accept only this canonical spelling, so that unlinking and `#i` lookups always match.
- **Proof** = base64 Bitcoin Signed Message signature by the key of `A` over the exact NIP-39 verification text:

  ```
  Verifying that I control the following Nostr public key: <npub of the event author>
  ```

  One ASCII line, no trailing newline. Message hash: `sha256(sha256("\x18Bitcoin Signed Message:\n" ‖
  compactSize(len) ‖ utf8(text)))`. Signature: `header ‖ r ‖ s` (65 bytes), header `27 + recid` for an uncompressed
  key, `31 + recid` for a compressed key.

**Alternative proof: on-chain commitment** (for wallets that sign transactions but not messages, e.g. WizardConnect
wallets such as Paytaca and Selene). Proof = `tx:<txid>` (64 lowercase hex). The transaction must:

- have an output whose locking bytecode is exactly `OP_RETURN <push of the UTF-8 verification text>`, and
- spend at least one P2PKH output locked to `A`.

Verify by fetching the transaction and every output it spends from any Bitcoin Cash node or Electrum server, checking
that each fetched transaction hashes to its txid (so the server cannot substitute data), and running the BCH virtual
machine on all inputs. A valid spend of `A`'s coin means the key of `A` signed a transaction naming this Nostr key.
The commitment is timestamped by the chain and costs only the network fee (~300 sats). Confirmation is not required
for validity: the signature is the proof.

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
   cashaddr. It MUST equal the claimed address. (For a `tx:` proof, verify the transaction as described in §1.)

If all hold, the BCH key holder named this Nostr key, and this Nostr key published this address: the binding is
valid. A claim copied into another user's list fails step 3–4; an edited event fails step 1.

**Which event counts.** Only the author's newest kind `10011` (highest `created_at`, ties broken by lowest id, as
NIP-01). A verifier that found an event through a `#i` search MUST fetch the author's newest list and require the
claim to be in it, because unlinking is done by publishing a newer list without the claim.

**What a valid claim proves.** "Whoever controls `A` signed this text naming this Nostr key." Public-key recovery
means any 65 random bytes recover to *some* address; such a claim is valid but points at an address nobody
controls, which gains nothing (like grinding a vanity address). Apps that need present control use the step-up (§4).

**Domain separation.** The text is NIP-39's generic one and does not mention Bitcoin Cash. So (a) a user must only
sign it for a Nostr key they mean to link: signing it on a hostile site that shows an attacker's npub links the
user's address to that npub; (b) the same signature from the same key could also be presented as a Bitcoin claim.
Wallets and pages should show the npub clearly before signing. Keeping NIP-39's text is a deliberate interop choice.

**Limits for verifiers.** Check a bounded number of claims per list (TwinKey: 16) and events per relay (200), and
keep only events that match the query, since relays are untrusted.

## 3. Discovery

- By Nostr key: `{"kinds":[10011],"authors":[<hex>]}`.
- By BCH address: `{"kinds":[10011],"#i":["bch:<id>"]}` (relays index single-letter tags). Verify each hit first
  and keep only authors whose hit holds a **valid** claim for the address (anyone can publish junk tags naming an
  address, but nobody can forge the signature, so junk never displaces a real link from the results), then require
  the claim in each such author's newest list. Limit: a verifier that caps events per relay can still have a real
  link pushed out of one relay's answer by a large flood of junk events; querying several relays helps, and lookup by
  Nostr key is not affected.
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

- DID view: `did:nostr:<hex>` with `alsoKnownAs` `did:pkh:bip122:000000000000000000651ef99cb9fcbe:<q… address>`
  (CAIP-2 chain id of Bitcoin Cash; CAIP-10 account ids exclude ':', so the cashaddr prefix is dropped).
- Payments: a wallet resolving a Nostr user to a BCH address SHOULD use only an address from a verified claim
  (BIP21 `bitcoincash:<address>?amount=…`).
- Wallet support needed: either "sign message" with a P2PKH key (Electron Cash; Paytaca and Cashonize via WalletConnect;
  mainnet-js), or "sign transaction" (WizardConnect: Paytaca, Selene) for the on-chain proof. WalletConnect
  `bch_signMessage` can produce the proof without copy-paste.
