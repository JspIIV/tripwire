// Deploy the Tripwire contract to GenLayer Bradbury with the pchg keystore.
//   PCHG=<pw> node scripts/deploy.mjs
import { Wallet } from 'ethers';
import fs from 'fs'; import os from 'os'; import path from 'path'; import url from 'url';
import { client, fees, EXPLORER } from './net.mjs';

const PW = process.env.PCHG || '';
if (!PW) { console.error('set PCHG'); process.exit(1); }
const ROOT = path.join(path.dirname(url.fileURLToPath(import.meta.url)), '..');
const KS = path.join(os.homedir(), '.genlayer', 'keystores');
const code = fs.readFileSync(path.join(ROOT, 'contracts', 'tripwire.py'), 'utf8');
const w = await Wallet.fromEncryptedJson(fs.readFileSync(path.join(KS, 'pchg.json'), 'utf8'), PW);
const c = client(w.privateKey);
console.log('deployer', w.address, 'source', code.length, 'bytes');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const show = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
const quote = await fees(c, { executionBudgetPerRound: BigInt(process.env.BUDGET || '50000000000000000') });
console.log('fee', Number(quote.feeValue) / 1e18, 'GEN');
const hash = await c.deployContract({ code, args: [], fees: quote });
console.log('tx', hash);

let addr = null, last = '';
for (let i = 0; i < 240; i++) {
  await sleep(10000);
  let tx = null;
  try { tx = await c.getTransaction({ hash }); } catch (e) { continue; }
  const state = `${tx.statusName} ${tx.txExecutionResultName || ''} ${tx.resultName || ''}`;
  if (state !== last) { console.log(`  ${(i + 1) * 10}s ${state}`); last = state; }
  addr = tx.txDataDecoded?.contractAddress || tx.recipient || addr;
  if (['FINALIZED', 'ACCEPTED'].includes(tx.statusName)) {
    if (tx.txExecutionResultName !== 'FINISHED_WITH_RETURN') { console.error('deploy failed:', state, 'tx', hash); process.exit(1); }
    if (addr) break;
  }
  if (['CANCELED', 'UNDETERMINED', 'LEADER_TIMEOUT', 'VALIDATORS_TIMEOUT'].includes(tx.statusName)) {
    console.log(show(tx).slice(0, 1500));
    process.exit(1);
  }
}
if (!addr) { console.error('no contract address; check tx', hash); process.exit(1); }
console.log('DEPLOYED', addr, EXPLORER + '/address/' + addr);
fs.writeFileSync(path.join(ROOT, 'deployment.json'), JSON.stringify(
  { network: 'genlayer testnet bradbury phase 2', address: addr, tx: hash, deployed_at: new Date().toISOString() }, null, 2));
process.exit(0);
