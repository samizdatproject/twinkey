// nostr-tools caches a successful check on the event object (a Symbol property). Object spread copies that
// symbol, so `{...verifiedEvent, pubkey: other}` would pass verifyEvent unchecked. Always verify a clean copy.
import { verifyEvent, type Event } from 'nostr-tools';

export function verifyEventFresh(event: Event): boolean {
  try {
    const { id, pubkey, created_at, kind, tags, content, sig } = event;
    return verifyEvent(JSON.parse(JSON.stringify({ id, pubkey, created_at, kind, tags, content, sig })));
  } catch {
    return false;
  }
}
