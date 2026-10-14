import assert from 'node:assert/strict'
import test from 'node:test'
import MultiSignature from './index.js'

test('signature envelopes retain canonical version, codec and signature bytes', () => {
  const signature = Uint8Array.from({ length: 64 }, (_, index) => index)
  for (const [version, codec, prefix] of [[0, 1, [0, 1]], [1, 1, [1, 1]], [129, 16384, [129, 1, 128, 128, 1]]]) {
    const multi = new MultiSignature(version, codec)
    const expected = new Uint8Array([...prefix, ...signature])
    assert.deepEqual(multi.encode(signature), expected)
    assert.deepEqual(multi.decode(expected), { version, multiCodec: codec, signature })
  }
})

test('keeps legacy padded headers and rejects truncated integer headers', () => {
  const signature = new Uint8Array(64).fill(42)
  const multi = new MultiSignature(1, 1)
  assert.deepEqual(multi.decode(new Uint8Array([129, 0, 129, 0, ...signature])), { version: 1, multiCodec: 1, signature })
  assert.throws(() => new MultiSignature(1, 1).decode(new Uint8Array([128])), /Truncated/)
})
