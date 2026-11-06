// The test contracts behind the Tripwire proof, on Base Sepolia.
//   PADV=<padv keystore password> node evm/deploy.mjs
// TokenV1, V2, V3 and every proxy are verified on Blockscout. TokenHidden is deliberately not.
import solc from 'solc';
import { Wallet, JsonRpcProvider, ContractFactory, Interface, AbiCoder } from 'ethers';
import fs from 'fs'; import os from 'os'; import path from 'path'; import url from 'url';

const ROOT = path.join(path.dirname(url.fileURLToPath(import.meta.url)), '..');
if (!process.env.PADV) { console.error('set PADV'); process.exit(1); }
const EXPLORER = 'https://base-sepolia.blockscout.com';
const EVM = 'cancun';
const compilerVersion = 'v' + solc.version().replace(/\.Emscripten.*$/, '');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function compile(name) {
  const source = fs.readFileSync(path.join(ROOT, 'evm', name + '.sol'), 'utf8');
  const out = JSON.parse(solc.compile(JSON.stringify({
    language: 'Solidity', sources: { [name + '.sol']: { content: source } },
    settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: EVM, outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } },
  })));
  const errs = (out.errors || []).filter((e) => e.severity === 'error');
  if (errs.length) { for (const e of errs) console.error(e.formattedMessage); process.exit(1); }
  const c = out.contracts[name + '.sol'][name];
  return { source, abi: c.abi, bytecode: '0x' + c.evm.bytecode.object };
}

const provider = new JsonRpcProvider('https://sepolia.base.org');
const ks = fs.readFileSync(path.join(os.homedir(), '.genlayer', 'keystores', 'padv.json'), 'utf8');
const wallet = (await Wallet.fromEncryptedJson(ks, process.env.PADV)).connect(provider);
const outFile = path.join(ROOT, 'results', 'contracts.json');
const done = fs.existsSync(outFile) ? JSON.parse(fs.readFileSync(outFile, 'utf8')) : {};
const save = () => fs.writeFileSync(outFile, JSON.stringify(done, null, 2));

async function deploy(name, label, args = []) {
  if (done[label]) return done[label].address;
  const c = compile(name);
  const contract = await new ContractFactory(c.abi, c.bytecode, wallet).deploy(...args);
  await contract.waitForDeployment();
  done[label] = { address: await contract.getAddress(), tx: contract.deploymentTransaction().hash, verified: false };
  save();
  console.log('deployed', label, done[label].address);
  return done[label].address;
}
async function verify(name, label, constructorArgs) {
  if (done[label].verified) return;
  const c = compile(name);
  for (let attempt = 1; attempt <= 6; attempt++) {
    const res = await fetch(`${EXPLORER}/api/v2/smart-contracts/${done[label].address}/verification/via/flattened-code`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ compiler_version: compilerVersion, license_type: 'mit', source_code: c.source,
        is_optimization_enabled: true, optimization_runs: 200, contract_name: name, evm_version: EVM,
        autodetect_constructor_args: !constructorArgs, constructor_args: constructorArgs || '', libraries: {} }),
    });
    console.log('  verify', label, res.status, (await res.text()).slice(0, 100));
    if (res.ok) break;
    await sleep(10000 * attempt);
  }
}

const v1 = await deploy('TokenV1', 'V1');
await deploy('TokenV2', 'V2');
await deploy('TokenV3', 'V3');
await deploy('TokenHidden', 'Hidden');
const init = new Interface(['function init()']).encodeFunctionData('init');
for (const p of ['ProxyA', 'ProxyB', 'ProxyC']) await deploy('PinnedProxy', p, [v1, init]);
await sleep(12000);
await verify('TokenV1', 'V1');
await verify('TokenV2', 'V2');
await verify('TokenV3', 'V3');
const args = AbiCoder.defaultAbiCoder().encode(['address', 'bytes'], [v1, init]).slice(2);
for (const p of ['ProxyA', 'ProxyB', 'ProxyC']) await verify('PinnedProxy', p, args);
await sleep(35000);
for (const label of Object.keys(done)) {
  const r = await fetch(`${EXPLORER}/api/v2/smart-contracts/${done[label].address}`).then((x) => x.json()).catch(() => ({}));
  done[label].verified = !!r.is_verified;
  console.log(label, done[label].address, 'verified:', !!r.is_verified, 'proxy:', r.proxy_type || null, JSON.stringify(r.implementations || []).slice(0, 90));
}
save();
process.exit(0);
