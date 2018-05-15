const test = require('tape');
const { encode } = require('bs58');
const MultiSignature = require('./');

const { leofcoin, buffer, version, codec, signee, signature } = {
  leofcoin: {
    address: 'oRBxBtoWiVGQomJSfQgWFHWLbGYGVqxvoL',
    signature: '5PyyMGDXpUaQmkZhytYeUYb6h3gRLcPTb'
  },
  buffer: encode(Buffer.alloc(32)),
  signee: encode(Buffer.alloc(32)),
  version: 0x00,
  codec: 0x01,
  signature: 'E5e13GehV2E7f8WRR6mWCV2tWmPrBY'
}

test('MultiSignature', tape => {
  tape.plan(5);
  const multi = new MultiSignature(version, codec);
	tape.equal(signature, multi.sign(buffer, signee), 'can sign');

  const multi2 = new MultiSignature(version, codec);
  tape.ok(multi2.verify(signature, buffer, signee), 'can verify');

  tape.equal(multi.export(), 'E5e13GehV2E7f8WRR6mWCV2tWmPrBY', 'can export multiSignature')

  const multi3 = new MultiSignature(0x00, 0x3c4);
  tape.equal(leofcoin.signature, multi3.sign(buffer, leofcoin.address), 'can sign leofcoin hash');

  const multi4 = new MultiSignature(0x00, 0x3c4);
  tape.ok(multi4.verify(leofcoin.signature, buffer, leofcoin.address), 'can verify leofcoin hash');
});
