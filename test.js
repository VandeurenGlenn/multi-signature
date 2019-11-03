const test = require('tape');
const { encode, decode } = require('bs58');
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
	tape.equal(signature.toString('hex'), multi.sign(buffer, signee).toString('hex'), 'can sign');

  const multi2 = new MultiSignature(version, codec);
  tape.ok(multi2.verify(signature, buffer, publicKey), 'can verify');

  tape.equal(multi.export(), encode(signature), 'can export multiSignature')

  const multi3 = new MultiSignature(0x00, 0x3c4);
  tape.equal(leofcoin.signature.toString('hex'), multi3.sign(buffer, leofcoin.address).toString('hex'), 'can sign leofcoin hash');
  // 
  const multi4 = new MultiSignature(0x00, 0x3c4);
  tape.ok(multi4.verify(leofcoin.signature, buffer, leofcoin.address), 'can verify leofcoin hash');
});
