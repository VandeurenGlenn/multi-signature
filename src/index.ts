import * as secp256k1 from "@noble/secp256k1";
import typedArrayConcat from "@vandeurenglenn/typed-array-concat";
import base58, { base58HexString, base58String } from "@vandeurenglenn/base58";
import base32, { base32HexString, base32String } from "@vandeurenglenn/base32";
import varint from "varint";
import { createHash } from "crypto";

secp256k1.hashes.sha256 = (message) => {
  message = Buffer.isBuffer(message) ? new Uint8Array(message) : message;
  return new Uint8Array(createHash("sha256").update(message).digest());
};
export default class MultiSignature {
  multiCodec: number;
  version: number;
  decoded!: {
    version: number;
    multiCodec: number;
    signature: Uint8Array;
  };
  encoded!: Uint8Array;

  #multiSignature!: Uint8Array;

  constructor(version: number | undefined, multiCodec: number | undefined) {
    if (version === undefined) throw ReferenceError("version undefined");
    if (multiCodec === undefined) throw ReferenceError("multicodec undefined");
    this.multiCodec = multiCodec;
    this.version = version;
  }

  get signature() {
    return this.decoded.signature;
  }

  get multiSignature() {
    return this.#multiSignature || this.encoded || this.encode(this.signature);
  }

  export() {
    return base58.encode(this.multiSignature);
  }

  import(encoded: base58String) {
    return base58.decode(encoded);
  }

  async sign(
    message: Uint8Array,
    privateKey: Uint8Array,
  ): Promise<multiSignature> {
    if (!message || !privateKey)
      throw ReferenceError(`${message ? "privateKey" : "message"} undefined`);

    // noble-secp256k1 expects hex strings or Uint8Array
    let signature = await secp256k1.schnorr.sign(message, privateKey);
    if (typeof signature === "string") {
      signature = Uint8Array.from(Buffer.from(signature, "hex"));
    }
    this.decoded = {
      version: this.version,
      multiCodec: this.multiCodec,
      signature,
    };
    return this.encode(this.decoded.signature);
  }

  /**
   * verify signature (multiSignature.signature)
   */
  async verifySignature(
    signature: MultiSignature["signature"],
    message: Uint8Array,
    publicKey: Uint8Array,
  ) {
    // Ensure only the last 64 bytes (r||s) are used for verification
    const sig = signature.length > 64 ? signature.slice(-64) : signature;
    return await secp256k1.schnorr.verify(sig, message, publicKey);
  }

  /**
   * verify multiSignature
   */
  async verify(
    multiSignature: MultiSignature["multiSignature"],
    message: Uint8Array,
    publicKey: Uint8Array,
  ) {
    // Ensure only the last 64 bytes (r||s) are used for verification
    const decoded = this.decode(multiSignature) as decodedMultiSignature;
    const sig =
      decoded.signature.length > 64
        ? decoded.signature.slice(-64)
        : decoded.signature;
    return await secp256k1.schnorr.verify(sig, message, publicKey);
  }

  encode(signature: Uint8Array): multiSignature {
    signature = signature || this.signature;
    if (!signature) throw ReferenceError("signature undefined");

    this.#multiSignature = typedArrayConcat([
      varint.encode(this.version),
      varint.encode(this.multiCodec),
      signature,
    ]);
    return this.multiSignature;
  }

  /**
   * decode exported multi signature to object
   * @param {multiSignature} multiSignature base58 encoded string
   * @return {decodedMultiSignature} { version, multiCodec, signature }
   */
  decode(
    multiSignature: MultiSignature["multiSignature"],
  ): decodedMultiSignature {
    if (multiSignature) this.#multiSignature = multiSignature;
    if (!this.multiSignature) throw ReferenceError("multiSignature undefined");
    let buffer = this.multiSignature;
    const version = varint.decode(buffer);
    buffer = buffer.subarray(varint.decode.bytes);

    const codec = varint.decode(buffer);
    buffer = buffer.subarray(varint.decode.bytes);

    const signature = buffer.subarray(0, buffer.length);
    console.log("[decode] extracted signature length:", signature.length);
    console.log(
      "[decode] extracted signature (hex):",
      Buffer.from(signature).toString("hex"),
    );
    if (version !== this.version) throw TypeError("Invalid version");
    if (this.multiCodec !== codec) throw TypeError("Invalid multiCodec");

    this.decoded = {
      version,
      multiCodec: codec,
      signature,
    };
    return this.decoded as decodedMultiSignature;
  }

  toString() {
    return this.multiSignature.toString();
  }

  fromString(string: string) {
    return this.decode(new Uint8Array(string.split(",")));
  }

  toBs58() {
    return base58.encode(this.multiSignature);
  }

  fromBs58(string: base58String) {
    return this.decode(base58.decode(string));
  }

  toBs32() {
    return base32.encode(this.multiSignature);
  }

  fromBs32(string: base32String) {
    return this.decode(base32.decode(string));
  }

  toBs32Hex() {
    return base32.encodeHex(this.multiSignature);
  }

  fromBs32Hex(string: base32HexString) {
    return this.decode(base32.decodeHex(string));
  }

  toBs58Hex() {
    return base58.encodeHex(this.multiSignature);
  }

  fromBs58Hex(string: base58HexString) {
    return this.decode(base58.decodeHex(string));
  }
}
