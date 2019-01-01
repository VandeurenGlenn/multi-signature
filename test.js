const test = require('tape');
const { encode } = require('bs58');
const MultiSignature = require('./');

const { buffer, version, codec, signee, signature, publicKey } = {
  buffer: Buffer.alloc(32),
  signee: Buffer.from('b4ecc3fc468b092e4ca9e5a859ef9f16d4cd94ac322ab443626bccbae291bc57', 'hex'),
  publicKey: Buffer.from('033f2870261a1f6e2a4a82ceb2032432c4fd606e818caab4ed9e8ec29f3c6d21ff', 'hex'),
  version: 0x00,
  codec: 0x01,
  signature: '1A24H3g28Ze7AadvZUusNWcNW9zHjhNrHkePaYzSMAXm6X4se6HGcxrmofwpB7v6Ck5eycTYo2wB5ZAGojjjBpKVs'
}

test('MultiSignature', tape => {
  tape.plan(3);
  const multi = new MultiSignature(version, codec);
	tape.equal(signature, multi.sign(buffer, signee), 'can sign');

  const multi2 = new MultiSignature(version, codec);
  tape.ok(multi2.verify(signature, buffer, publicKey), 'can verify');

  tape.equal(multi.export(), signature, 'can export multiSignature')
});
