#!/usr/bin/env node
/** Read-only independent fixture cross-check using ALREADY INSTALLED/LOCKED JS libs.
 * No npm install, production imports, avault outputs, secrets, or network access.
 * Writes only js-verification.json beside this file.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, isAbsolute, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(fileURLToPath(import.meta.url));
const PROJECT = process.env.HD_FIXTURE_JS_PROJECT;
assert.ok(PROJECT && isAbsolute(PROJECT),
  'Set HD_FIXTURE_JS_PROJECT explicitly to the absolute path of an existing project with the recorded installed/locked libraries.');
const require = createRequire(join(PROJECT, 'package.json'));
const { HDKey } = require('@scure/bip32');
const { mnemonicToSeedSync, mnemonicToEntropy, entropyToMnemonic, validateMnemonic } = require('@scure/bip39');
const { wordlist } = require('@scure/bip39/wordlists/english');
const { base58check, bech32, bech32m } = require('@scure/base');
const { sha256, sha512 } = await import(require.resolve('@noble/hashes/sha2.js'));
const { ripemd160 } = await import(require.resolve('@noble/hashes/legacy.js'));
const { hmac } = await import(require.resolve('@noble/hashes/hmac.js'));
const { secp256k1, schnorr } = await import(require.resolve('@noble/curves/secp256k1.js'));
const { ed25519 } = await import(require.resolve('@noble/curves/ed25519.js'));
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const bytes = (value) => Uint8Array.from(Buffer.from(value, 'hex'));
const utf8 = (value) => new TextEncoder().encode(value);
const cat = (...arrays) => Uint8Array.from(Buffer.concat(arrays.map((a) => Buffer.from(a))));
const sha = (data) => createHash('sha256').update(data).digest('hex');
const fixtureBytes = readFileSync(join(ROOT, 'hd-public-fixtures.json'));
const fixture = JSON.parse(fixtureBytes);
const entropy = JSON.parse(readFileSync(join(ROOT, 'public-entropy.json')));
const lockBytes = readFileSync(join(PROJECT, 'package-lock.json'));
const lock = JSON.parse(lockBytes);
const packagePaths = ['node_modules/@scure/bip32', 'node_modules/@scure/bip39', 'node_modules/@scure/base',
  'node_modules/@noble/curves', 'node_modules/@noble/hashes',
  'node_modules/@scure/bip32/node_modules/@noble/curves',
  'node_modules/@scure/bip32/node_modules/@noble/hashes',
  'node_modules/@scure/bip39/node_modules/@noble/hashes'];
function treeDigest(directory) {
  const entries = [];
  function visit(current) {
    for (const entry of readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name, 'en'))) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue;
      const path = join(current, entry.name);
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile() && /\.(js|json)$/.test(entry.name)) entries.push([relative(directory, path), sha(readFileSync(path))]);
    }
  }
  visit(directory);
  entries.sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
  return { files: entries.length, sha256_of_sorted_path_sha256_json: sha(JSON.stringify(entries)) };
}
const packages = packagePaths.map((path) => {
  const installed = JSON.parse(readFileSync(join(PROJECT, path, 'package.json')));
  const pinned = lock.packages[path];
  assert.ok(pinned && pinned.integrity && pinned.resolved, `must be locked: ${path}`);
  assert.equal(installed.version, pinned.version, path);
  return { path, name: installed.name, version: installed.version,
    url: pinned.resolved, integrity: pinned.integrity, installed_code_tree: treeDigest(join(PROJECT, path)) };
});
assert.equal(packages[0].version, '1.7.0');
assert.equal(packages[1].version, '1.6.0');
assert.equal(packages[2].version, '1.2.6');
assert.equal(packages[3].version, '2.2.0');
assert.equal(packages[4].version, '2.2.0');

const checks = { cases: 0, accounts: 0, mnemonic_seed_comparisons: 0, public_key_comparisons: 0,
  output_key_comparisons: 0, address_comparisons: 0, address_decode_roundtrips: 0,
  wrong_purpose_reencodings_rejected: 0, unicode_nfkd_equivalences: 0, slip10_official_ed25519_nodes: 0 };
const base58 = base58check(sha256);
const hash160 = (data) => ripemd160(sha256(data));
const address0 = (publicKey) => base58.encode(cat(Uint8Array.of(0), hash160(publicKey)));
const addressW = (publicKey) => bech32.encode('bc', [0, ...bech32.toWords(hash160(publicKey))]);
const addressT = (output) => bech32m.encode('bc', [1, ...bech32m.toWords(output)]);
function slip10(seed, path) {
  let material = hmac(sha512, utf8('ed25519 seed'), seed);
  for (const component of path.split('/').slice(1)) {
    assert.match(component, /^\d+'$/);
    const index = Number(component.slice(0, -1)) + 0x80000000;
    const data = new Uint8Array(37);
    data.set(material.subarray(0, 32), 1);
    new DataView(data.buffer).setUint32(33, index, false);
    material = hmac(sha512, material.subarray(32), data);
  }
  return { key: material.subarray(0, 32), chain: material.subarray(32) };
}
function outputKey(internal) {
  const x = internal.subarray(1);
  const evenP = secp256k1.Point.fromBytes(cat(Uint8Array.of(2), x));
  const tweak = BigInt('0x' + hex(schnorr.utils.taggedHash('TapTweak', x)));
  assert.ok(tweak < secp256k1.Point.Fn.ORDER);
  const Q = tweak === 0n ? evenP : evenP.add(secp256k1.Point.BASE.multiply(tweak));
  assert.ok(!Q.is0());
  return Q.toBytes(true).subarray(1);
}

assert.deepEqual(Object.keys(fixture).sort(), ['cases', 'sources']);
assert.equal(fixture.cases.length, 7);
assert.equal(new Set(fixture.cases.map((c) => c.seed_hex)).size, 7);
const sourceManifest = JSON.parse(readFileSync(join(ROOT, 'sources-manifest.json')));
assert.deepEqual(fixture.sources, sourceManifest.map(({ url, sha256 }) => ({ url, sha256 })));
for (const entry of sourceManifest) assert.equal(sha(readFileSync(join(ROOT, entry.file))), entry.sha256);
assert.deepEqual(wordlist, readFileSync(join(ROOT, 'sources/bitcoin/bips/bip-0039/english.txt'), 'utf8').trim().split('\n'));

for (const testCase of fixture.cases) {
  assert.deepEqual(Object.keys(testCase).sort(), ['accounts', 'id', 'mnemonic', 'nfkd_passphrase', 'passphrase', 'seed_hex']);
  assert.ok(validateMnemonic(testCase.mnemonic, wordlist), testCase.id);
  assert.equal(testCase.nfkd_passphrase, testCase.passphrase.normalize('NFKD'));
  const entropyBytes = mnemonicToEntropy(testCase.mnemonic, wordlist);
  assert.equal(entropyToMnemonic(entropyBytes, wordlist), testCase.mnemonic);
  if (testCase.id.startsWith('random')) {
    const fixed = entropy.mnemonics.find((e) => testCase.id.startsWith(e.id + '_'));
    assert.ok(fixed);
    assert.equal(hex(entropyBytes), fixed.entropy_hex);
    assert.equal(testCase.mnemonic.split(' ').length, fixed.words);
  } else {
    assert.equal(testCase.id, 'bip39_abandon11_about_empty');
    assert.equal(testCase.mnemonic, Array(11).fill('abandon').concat('about').join(' '));
    assert.equal(testCase.passphrase, '');
  }
  const seed = mnemonicToSeedSync(testCase.mnemonic, testCase.passphrase);
  assert.equal(seed.length, 64);
  assert.equal(hex(seed), testCase.seed_hex, testCase.id);
  if (testCase.id.endsWith('unicode_nfkd')) {
    assert.notEqual(testCase.passphrase, testCase.nfkd_passphrase);
    assert.equal(hex(mnemonicToSeedSync(testCase.mnemonic, testCase.nfkd_passphrase)), testCase.seed_hex);
    checks.unicode_nfkd_equivalences++;
  }
  checks.mnemonic_seed_comparisons++;
  const root = HDKey.fromMasterSeed(seed);
  assert.equal(testCase.accounts.length, 20);
  for (let i = 0; i < 20; i++) {
    const expected = testCase.accounts[i];
    assert.deepEqual(Object.keys(expected).sort(), ['account', 'addresses', 'bitcoin', 'bitcoin_output_key', 'bitcoin_p2pkh', 'bitcoin_p2wpkh', 'evm', 'solana']);
    assert.deepEqual(Object.keys(expected.addresses).sort(), ['p2pkh', 'p2tr', 'p2wpkh']);
    assert.equal(expected.account, i);
    const nodes = {
      evm: root.derive(`m/44'/60'/0'/0/${i}`),
      bitcoin: root.derive(`m/86'/0'/0'/0/${i}`),
      bitcoin_p2pkh: root.derive(`m/44'/0'/0'/0/${i}`),
      bitcoin_p2wpkh: root.derive(`m/84'/0'/0'/0/${i}`),
    };
    for (const [name, node] of Object.entries(nodes)) {
      assert.match(expected[name], /^(02|03)[0-9a-f]{64}$/);
      assert.equal(hex(node.publicKey), expected[name], `${testCase.id}/${i}/${name}`);
      // Also compare top-level noble v2 (HDKey internally uses pinned noble v1).
      assert.equal(hex(secp256k1.getPublicKey(node.privateKey, true)), expected[name]);
      checks.public_key_comparisons++;
    }
    const sol = slip10(seed, `m/44'/501'/${i}'/0'`);
    assert.match(expected.solana, /^[0-9a-f]{64}$/);
    assert.equal(hex(ed25519.getPublicKey(sol.key)), expected.solana, `${testCase.id}/${i}/solana`);
    checks.public_key_comparisons++;
    const output = outputKey(nodes.bitcoin.publicKey);
    assert.equal(hex(output), expected.bitcoin_output_key);
    checks.output_key_comparisons++;
    const addresses = {
      p2pkh: address0(nodes.bitcoin_p2pkh.publicKey),
      p2wpkh: addressW(nodes.bitcoin_p2wpkh.publicKey),
      p2tr: addressT(output),
    };
    assert.deepEqual(addresses, expected.addresses, `${testCase.id}/${i}/addresses`);
    checks.address_comparisons += 3;
    assert.equal(hex(base58.decode(addresses.p2pkh)), hex(cat(Uint8Array.of(0), hash160(nodes.bitcoin_p2pkh.publicKey))));
    for (const [kind, codec, version, program] of [
      ['p2wpkh', bech32, 0, hash160(nodes.bitcoin_p2wpkh.publicKey)], ['p2tr', bech32m, 1, output]]) {
      const decoded = codec.decode(addresses[kind]);
      assert.equal(decoded.prefix, 'bc');
      assert.equal(decoded.words[0], version);
      assert.equal(hex(codec.fromWords(decoded.words.slice(1))), hex(program));
    }
    checks.address_decode_roundtrips += 3;
    assert.notEqual(address0(nodes.bitcoin.publicKey), expected.addresses.p2pkh);
    assert.notEqual(addressW(nodes.bitcoin.publicKey), expected.addresses.p2wpkh);
    checks.wrong_purpose_reencodings_rejected += 2;
    checks.accounts++;
  }
  checks.cases++;
}

const slipText = readFileSync(join(ROOT, 'sources/satoshilabs/slips/slip-0010.md'), 'utf8');
for (const group of slipText.matchAll(/### Test vector [12] for ed25519\n([\s\S]*?)(?=\n###|$)/g)) {
  const seed = bytes(group[1].match(/Seed \(hex\): ([0-9a-f]+)/)[1]);
  for (const node of group[1].matchAll(/\* Chain ([^\n]+)\n([\s\S]*?)(?=\n\* Chain|$)/g)) {
    const path = node[1].replaceAll('<sub>H</sub>', "'");
    const fields = Object.fromEntries([...node[2].matchAll(/\* (chain code|private|public): ([0-9a-f]+)/g)].map((m) => [m[1], m[2]]));
    const derived = slip10(seed, path);
    assert.equal(hex(derived.key), fields.private);
    assert.equal(hex(derived.chain), fields['chain code']);
    assert.equal('00' + hex(ed25519.getPublicKey(derived.key)), fields.public);
    checks.slip10_official_ed25519_nodes++;
  }
}
assert.deepEqual(checks, { cases: 7, accounts: 140, mnemonic_seed_comparisons: 7,
  public_key_comparisons: 700, output_key_comparisons: 140, address_comparisons: 420,
  address_decode_roundtrips: 420, wrong_purpose_reencodings_rejected: 280,
  unicode_nfkd_equivalences: 2, slip10_official_ed25519_nodes: 12 });
const evidence = { status: 'PASS', node: process.version, fixture_sha256: sha(fixtureBytes),
  package_lock_sha256: sha(lockBytes), packages, checks };
writeFileSync(join(ROOT, 'js-verification.json'), JSON.stringify(evidence, null, 2) + '\n');
console.log(JSON.stringify({ status: evidence.status, fixture_sha256: evidence.fixture_sha256, checks }, null, 2));
