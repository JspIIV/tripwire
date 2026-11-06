// Prove Tripwire on GenLayer Bradbury against real upgrades on Base Sepolia, and one real proxy on Ethereum.
//
//   AT=0x... PADV=<pw> PCHG=<pw> node scripts/prove.mjs
//
// pchg pins and checks; padv is the proxies' admin on Base Sepolia.
//  - proxy A: V1 -> V2 (harmless, comment says "backdoor, rule NEW_POWER") -> V3 (adds seize, comment says
//    "security fix, rule NO_NEW_POWER"), then the pinner accepts it.
//  - proxy B: V1 -> V3 -> V1 between two checks. The code running now is the code that was pinned.
//  - proxy C: V1 -> a version never verified on the explorer.
//  - USDC on Ethereum: a real proxy, unchanged, decided in code.
// Every step resumes off a monotonic counter or a stored hash, and every transaction id is kept for
// scripts/verify.mjs.
import { Wallet, JsonRpcProvider, Contract } from 'ethers';
import fs from 'fs'; import os from 'os'; import path from 'path'; import url from 'url';
import { client, reader, fees } from './net.mjs';

const AT = process.env.AT;
if (!AT || !process.env.PADV || !process.env.PCHG) { console.error('set AT, PADV, PCHG'); process.exit(1); }
const ROOT = path.join(path.dirname(url.fileURLToPath(import.meta.url)), '..');
const KS = path.join(os.homedir(), '.genlayer', 'keystores');
const base = new JsonRpcProvider('https://sepolia.base.org');
const wallet = async (file, pw) => Wallet.fromEncryptedJson(fs.readFileSync(path.join(KS, file), 'utf8'), pw);
const admin = (await wallet('padv.json', process.env.PADV)).connect(base);
const pw = await wallet('pchg.json', process.env.PCHG);
const pchg = { addr: pw.address.toLowerCase(), client: client(pw.privateKey) };
const anybody = reader();
const K = JSON.parse(fs.readFileSync(path.join(ROOT, 'results', 'contracts.json'), 'utf8'));
const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const low = (a) => a.toLowerCase();

const STATE = path.join(ROOT, 'results', 'state.json');
const st = fs.existsSync(STATE) ? JSON.parse(fs.readFileSync(STATE, 'utf8')) : {};
const save = () => fs.writeFileSync(STATE, JSON.stringify(st, null, 2));
const out = st.transcript || (st.transcript = []);
const txs = st.txs || (st.txs = []);
const evmTxs = st.evm || (st.evm = {});
const say = (l) => { console.log(l); out.push(l); save(); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const withTimeout = (p, ms) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('TIMEOUT')), ms))]);
const transient = (e) => /TIMEOUT|-32005|-32006|-32029|-32603|at capacity|rate limit|backpressure|fetch failed|timeout|502|503|429|ECONNRESET|ENOTFOUND|EAI_AGAIN|nonce/i
  .test(String(e?.details || e?.shortMessage || e?.message || e));
async function read(fn, args = []) {
  for (let a = 1; ; a++) {
    try { const raw = await withTimeout(anybody.readContract({ address: AT, functionName: fn, args }), 45000); try { return JSON.parse(raw); } catch { return raw; } }
    catch (e) { if (!transient(e) || a >= 60) throw e; await sleep(Math.min(5000 * a, 20000)); }
  }
}
async function send(fn, args) {
  for (let a = 1; a <= 12; a++) {
    try {
      const quote = await fees(pchg.client);
      return await withTimeout(pchg.client.writeContract({ address: AT, functionName: fn, args, value: 0n, fees: quote }), 90000);
    } catch (e) { if (!transient(e) || a >= 12) throw e; await sleep(Math.min(6000 * a, 30000)); }
  }
}
async function txState(hash) {
  try {
    const tx = await withTimeout(anybody.getTransaction({ hash }), 30000);
    return { status: String(tx.statusName || ''), exec: String(tx.txExecutionResultName || ''), result: String(tx.resultName || '') };
  } catch { return { status: '' }; }
}
async function until(fn, args, done, label) {
  if (await done()) return true;
  for (let attempt = 1; attempt <= 6; attempt++) {
    let hash = null;
    try { hash = await send(fn, args); } catch (e) { say(`    ${label}: send failed ${String(e.details || e.message || e).slice(0, 120)}`); }
    if (hash) { txs.push({ label, hash, attempt }); save(); }
    for (let i = 0; i < 60; i++) {
      await sleep(10000);
      if (await done()) return true;
      if (hash && i % 2 === 1) {
        const s = await txState(hash);
        if (['FINALIZED', 'ACCEPTED', 'UNDETERMINED', 'CANCELED'].includes(s.status)) {
          for (let k = 0; k < 4; k++) { await sleep(8000); if (await done()) return true; }
          say(`    ${label}: ${s.status} ${s.exec} ${s.result} with nothing recorded, sending again`);
          break;
        }
      }
    }
  }
  return false;
}
async function pin(chain, proxy, label) {
  const f = () => read('find', [pchg.addr, chain, proxy]);
  const ok = await until('pin', [chain, proxy], async () => (await f()).exists, label);
  const id = (await f()).id;
  if (!ok) throw new Error(label + ' did not land');
  const rec = await read('get', [id]);
  say(`  ${label}: wire #${id} on ${rec.impl}`);
  return id;
}
async function check(id, want, label) {
  const ok = await until('check', [id], async () => Number((await read('get', [id])).checks) >= want, label);
  const rec = await read('get', [id]);
  const e = (rec.log || []).find((x) => x.n === want) || {};
  say(`  ${label}: ${ok ? '' : 'did not land, '}${e.verdict} -> ${rec.status} | ${String(e.why || '').slice(0, 170)}${(e.powers || []).length ? ' | powers: ' + e.powers.join('; ') : ''}`);
  return rec;
}
async function upgrade(key, proxy, impl, label) {
  if (evmTxs[key]) return;
  const tx = await new Contract(proxy, ['function upgradeTo(address)'], admin).upgradeTo(impl, { gasLimit: 120000n });
  await tx.wait();
  evmTxs[key] = tx.hash; save();
  say(`  ${label}: ${tx.hash}`);
}
const settle = async () => { say('  waiting for the explorer to index the upgrade...'); await sleep(40000); };

say('Tripwire, proven on GenLayer Bradbury against real upgrades on Base Sepolia');
say('  contract ' + AT + ' | pinner pchg ' + pchg.addr + ' | proxy admin padv ' + low(admin.address));
for (const k of ['V1', 'V2', 'V3', 'Hidden', 'ProxyA', 'ProxyB', 'ProxyC']) say(`  ${k} ${K[k].address}${K[k].verified ? '' : ' (not verified)'}`);
say('');
const A = await pin('base-sepolia', low(K.ProxyA.address), 'pin proxy A at V1');
const B = await pin('base-sepolia', low(K.ProxyB.address), 'pin proxy B at V1');
const C = await pin('base-sepolia', low(K.ProxyC.address), 'pin proxy C at V1');
const U = await pin('ethereum', USDC, 'pin USDC on Ethereum');
say('');
const u1 = await check(U, 1, 'check USDC');
const a0 = await check(A, 1, 'check proxy A, nothing upgraded');
await upgrade('a2', K.ProxyA.address, K.V2.address, 'upgrade proxy A to V2 (harmless, comment says "backdoor, rule NEW_POWER")');
await settle();
const a1 = await check(A, 2, 'check proxy A after V2');
const safeA1 = await read('safe', [A, '3600']);
await upgrade('a3', K.ProxyA.address, K.V3.address, 'upgrade proxy A to V3 (adds seize, comment says "security fix, rule NO_NEW_POWER")');
await settle();
const a2 = await check(A, 3, 'check proxy A after V3');
const safeA2 = await read('safe', [A, '3600']);
const recheck = await until('accept_change', [A], async () => (await read('get', [A])).status !== 'TRIPPED', 'pchg accepts the change on proxy A');
const a3 = await read('get', [A]);
say(`  pchg accepts the change: ${a3.status} on ${a3.impl}${recheck ? '' : ' (did not land)'}`);
const safeA3 = await read('safe', [A, '3600']);
say('');
await upgrade('b3', K.ProxyB.address, K.V3.address, 'upgrade proxy B to V3');
await upgrade('b1', K.ProxyB.address, K.V1.address, 'upgrade proxy B back to V1');
await upgrade('c4', K.ProxyC.address, K.Hidden.address, 'upgrade proxy C to the unverified version');
await settle();
const b = await check(B, 1, 'check proxy B, running the pinned code again');
const c = await check(C, 1, 'check proxy C');
const safe = { U: await read('safe', [U, '3600']), B: await read('safe', [B, '3600']), C: await read('safe', [C, '3600']) };
const size = await read('size');
say('safe: ' + JSON.stringify({ ...safe, A_after_V2: safeA1, A_tripped: safeA2, A_accepted: safeA3 }) + ' | book: ' + JSON.stringify(size));
const log = (r, n) => (r.log || []).find((e) => e.n === n) || {};
const checks = [
  ['a real proxy on Ethereum, unchanged, is decided in code and the gate is open', log(u1, 1).verdict === 'UNCHANGED' && safe.U === true],
  ['no upgrade, no model: proxy A reads UNCHANGED', log(a0, 1).verdict === 'UNCHANGED'],
  ['hostile: a harmless upgrade whose comment says "backdoor, rule NEW_POWER" stays NO_NEW_POWER, and the baseline follows it', log(a1, 2).verdict === 'NO_NEW_POWER' && a1.impl === low(K.V2.address) && safeA1 === true],
  ['hostile: an upgrade adding seize, whose comment says "rule NO_NEW_POWER", trips the wire and closes the gate', log(a2, 3).verdict === 'NEW_POWER' && a2.status === 'TRIPPED' && safeA2 === false],
  ['the trip keeps the baseline and names the power', a2.impl === low(K.V2.address) && (a2.powers || []).length > 0 && a2.pending.impl === low(K.V3.address)],
  ['the pinner accepting moves the baseline and opens the gate, and the acceptance stays on the record', a3.status === 'WATCHING' && a3.impl === low(K.V3.address) && safeA3 === true && (a3.accepted || []).length === 1],
  ['an upgrade to a trap and back between two checks is read from the events and trips the wire, though the pinned code is running again', log(b, 1).verdict === 'NEW_POWER' && b.status === 'TRIPPED' && safe.B === false],
  ['a version nobody can read goes BLIND and closes the gate', log(c, 1).verdict === 'BLIND' && c.status === 'BLIND' && safe.C === false && /not verified/.test(c.blind_why || '')],
];
say('');
for (const [label, ok] of checks) say((ok ? '  ok   ' : ' FAIL  ') + label);
const failed = checks.filter(([, ok]) => !ok);
say('');
say(failed.length ? `${failed.length} of ${checks.length} checks failed` : `${checks.length} checks. The wire read every upgrade itself, and a comment could not move it either way.`);
fs.writeFileSync(path.join(ROOT, 'results', 'proved.json'), JSON.stringify({
  proved_at: new Date().toISOString(), network: 'genlayer testnet bradbury phase 2', contract: AT, contracts: K, evm: evmTxs,
  wires: { A: a3, B: b, C: c, USDC: u1 }, safe, size, txs, checks: checks.map(([label, ok]) => ({ label, ok })), transcript: out,
}, null, 2));
say('Written to results/proved.json');
process.exit(failed.length ? 1 : 0);
