// A throwaway in-memory relay on ws://127.0.0.1:7447 for trying TwinKey offline (put it in the Relays box).
import { startMockRelay } from '../test/mock-relay.ts';
const r = await startMockRelay(Number(process.env.PORT ?? 7447));
console.log(`dev relay on ${r.url} (in memory; Ctrl-C to stop)`);
