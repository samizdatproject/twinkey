// Try examples/auth-server.ts end to end: makes a fresh identity, publishes its link, logs in with the BCH step-up,
// then shows the replay being refused.  RELAYS=ws://127.0.0.1:7447 npm run auth-server  then  npm run auth-client
import { generatePrivateKey } from '@bitauth/libauth';
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools';
import { addressOf, signMessage } from '../src/lib/bchmsg.ts';
import { claimTag, identityTemplate, verificationText } from '../src/lib/claim.ts';
import { publish } from '../src/lib/relays.ts';
import { authHeader, authTemplate, bchLoginText } from '../src/lib/auth.ts';
const bch = generatePrivateKey(); const sk = generateSecretKey(); const pub = getPublicKey(sk); const addr = addressOf(bch);
await publish(finalizeEvent(identityTemplate([claimTag(addr, signMessage(bch, verificationText(pub)))]), sk), (process.env.RELAYS ?? 'ws://127.0.0.1:7447').split(','));
const c = await (await fetch(`${process.env.SERVER ?? 'http://127.0.0.1:8788'}/challenge`)).json();
const ev = finalizeEvent(authTemplate(c), sk);
const r = await fetch(c.url, { method: 'POST', headers: { authorization: authHeader(ev), 'x-bch-signature': signMessage(bch, bchLoginText(c, pub)) } });
console.log(r.status, await r.text());
const replay = await fetch(c.url, { method: 'POST', headers: { authorization: authHeader(ev) } });
console.log('replay', replay.status);
