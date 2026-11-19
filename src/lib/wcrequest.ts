// The WizardConnect sign request in the relay-safe encoding the protocol expects (hex strings and "<bigint: Xn>").
// Raw libauth objects carry bigints, which JSON cannot encode: sending them fails before the wallet sees anything.
import { sourceOutputToRelay, transactionToHex } from '@wizardconnect/core/hdwalletv1-serialize';
import type { UnsignedTx } from './txproof.ts';

export function wizardSignRequest(u: UnsignedTx, userPrompt: string) {
  const t = u.transaction;
  return {
    transaction: transactionToHex(t.inputs, t.outputs, t.version, t.locktime),
    sourceOutputs: u.sourceOutputs.map(sourceOutputToRelay),
    broadcast: true,
    userPrompt,
  };
}
