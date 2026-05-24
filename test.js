import { createHash } from "crypto";
import { test } from "node:test";
import assert from "node:assert/strict";
import MultiSignature from "./index.js";

const privateKey = new Uint8Array([
  70, 104, 127, 235, 242, 158, 53, 129, 32, 95, 3, 113, 190, 192, 153, 50, 14,
  126, 187, 196, 56, 173, 189, 17, 253, 187, 87, 165, 52, 215, 68, 115,
]);

const publicKey = new Uint8Array([
  59, 241, 162, 229, 72, 24, 7, 120, 85, 45, 175, 79, 122, 126, 58, 56, 48, 59,
  21, 177, 153, 174, 42, 93, 54, 210, 1, 120, 53, 199, 55, 33,
]);

function createMessage(text) {
  return createHash("sha256").update(Buffer.from(text), "utf8").digest();
}

test("MultiSignature schnorr sign/verify", async (t) => {
  const version = 0x01;
  const codec = 0x01;
  const multi = new MultiSignature(version, codec);

  const message = createMessage("test message schnorr");
  await multi.sign(message, privateKey);
  const msig = multi.multiSignature;
  const verified = await multi.verify(msig, message, publicKey);
  assert.ok(verified, "MultiSignature schnorr sign/verify works");
});

test("MultiSignature schnorr sign/verify version 0x00", async (t) => {
  const version = 0x00;
  const codec = 0x01;
  const multi = new MultiSignature(version, codec);

  const message = createMessage("test message schnorr");
  await multi.sign(message, privateKey);
  const msig = multi.multiSignature;
  const verified = await multi.verify(msig, message, publicKey);
  assert.ok(
    verified,
    "MultiSignature schnorr sign/verify works for version 0x00",
  );
});

test("MultiSignature constructor requires version and codec", () => {
  assert.throws(() => new MultiSignature(undefined, 0x01), /version undefined/);
  assert.throws(
    () => new MultiSignature(0x01, undefined),
    /multicodec undefined/,
  );
});

test("MultiSignature sign requires hash and private key", async () => {
  const multi = new MultiSignature(0x01, 0x01);
  const message = createMessage("missing args");

  await assert.rejects(multi.sign(undefined, privateKey), /message undefined/);
  await assert.rejects(multi.sign(message, undefined), /privateKey undefined/);
});

test("MultiSignature encode and decode round-trip", () => {
  const multi = new MultiSignature(0x01, 0x01);
  const signature = Uint8Array.from({ length: 64 }, (_, index) => index);

  const encoded = multi.encode(signature);
  const decoded = multi.decode(encoded);

  assert.deepEqual(decoded, {
    version: 0x01,
    multiCodec: 0x01,
    signature,
  });
  assert.deepEqual(multi.multiSignature, encoded);
});

test("MultiSignature serializes and deserializes across encodings", async () => {
  const version = 0x01;
  const codec = 0x01;
  const multi = new MultiSignature(version, codec);
  const message = createMessage("round trip");

  await multi.sign(message, privateKey);

  const msig = multi.multiSignature;
  const bs58 = multi.toBs58();
  const bs32 = multi.toBs32();
  const bs32Hex = multi.toBs32Hex();
  const bs58Hex = multi.toBs58Hex();

  assert.deepEqual(multi.import(bs58), msig);
  assert.equal(multi.export(), bs58);
  assert.deepEqual(multi.fromBs58(bs58), multi.decoded);
  assert.deepEqual(multi.fromBs32(bs32), multi.decoded);
  assert.deepEqual(multi.fromBs32Hex(bs32Hex), multi.decoded);
  assert.deepEqual(multi.fromBs58Hex(bs58Hex), multi.decoded);
  assert.equal(multi.signature.length, 64);
  assert.equal(multi.decoded.version, version);
  assert.equal(multi.decoded.multiCodec, codec);
});

test("MultiSignature decode rejects mismatched version and codec", async () => {
  const message = createMessage("decode mismatch");
  const source = new MultiSignature(0x01, 0x01);
  await source.sign(message, privateKey);
  const msig = source.multiSignature;

  assert.throws(
    () => new MultiSignature(0x02, 0x01).decode(msig),
    /Invalid version/,
  );
  assert.throws(
    () => new MultiSignature(0x01, 0x02).decode(msig),
    /Invalid multiCodec/,
  );
});

test("MultiSignature verification fails for tampered inputs", async () => {
  const multi = new MultiSignature(0x01, 0x01);
  const message = createMessage("tamper check");

  await multi.sign(message, privateKey);
  const msig = multi.multiSignature;

  const tamperedSignature = new Uint8Array(multi.signature);
  tamperedSignature[tamperedSignature.length - 1] ^= 0x01;
  const tamperedMsig = new Uint8Array(msig);
  tamperedMsig[tamperedMsig.length - 1] ^= 0x01;
  const wrongPublicKey = new Uint8Array(publicKey);
  wrongPublicKey[0] ^= 0x01;

  assert.equal(
    await multi.verifySignature(tamperedSignature, message, publicKey),
    false,
  );
  assert.equal(await multi.verify(tamperedMsig, message, publicKey), false);
  assert.equal(await multi.verify(msig, message, wrongPublicKey), false);
});
