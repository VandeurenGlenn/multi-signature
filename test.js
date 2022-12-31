import test from'tape'
import base58 from '@vandeurenglenn/base58'
import MultiSignature from './index.js'
const stringEncoded = '0,1,195,16,102,158,127,42,238,9,169,159,16,118,5,238,43,39,102,111,122,112,24,193,115,45,96,124,206,243,118,175,169,206,104,95,202,26,241,176,17,58,18,175,58,246,64,112,79,90,6,156,132,55,176,61,158,88,77,159,125,162,215,187,6,202'
const { buffer, version, codec, signee, signature, publicKey, signatureBase58 } = {
  buffer: new Uint8Array(32),
  signee: new Uint8Array(Buffer.from('b4ecc3fc468b092e4ca9e5a859ef9f16d4cd94ac322ab443626bccbae291bc57', 'hex')),
  publicKey: new Uint8Array(Buffer.from('033f2870261a1f6e2a4a82ceb2032432c4fd606e818caab4ed9e8ec29f3c6d21ff', 'hex')),
  version: 0x00,
  codec: 0x01,
  
  signature: new Uint8Array(stringEncoded.split(',')),
  signatureBase58: '1A24H3g28Ze7AadvZUusNWcNW9zHjhNrHkePaYzSMAXm6X4se6HGcxrmofwpB7v6Ck5eycTYo2wB5ZAGojjjBpKVs'
}

test('MultiSignature', tape => {
  tape.plan(7);
  const multi = new MultiSignature(version, codec);
  multi.sign(buffer, signee)
  const base58Encoded = multi.toBs58()
  console.log(base58Encoded);
	tape.equal(signatureBase58, base58Encoded, 'can sign');
  

  const multi2 = new MultiSignature(version, codec);
  tape.ok(multi2.verify(base58.decode(signatureBase58), buffer, publicKey), 'can verify');
  

  tape.equal(multi.export(), signatureBase58, 'can export multiSignature')
  
  multi.fromString(stringEncoded)
  tape.deepEqual(base58.decode(base58Encoded), multi.multiSignature, 'can load from string');

  multi.fromBs58(base58Encoded)
  tape.deepEqual(base58.decode(base58Encoded), multi.multiSignature, 'can load from base58');

  multi.fromBs32(multi.toBs32())
  tape.deepEqual(base58.decode(base58Encoded), multi.multiSignature, 'can load from base32');

  multi.fromBs32Hex(multi.toBs32Hex())
  tape.deepEqual(base58.decode(base58Encoded), multi.multiSignature, 'can load from base32');
});
