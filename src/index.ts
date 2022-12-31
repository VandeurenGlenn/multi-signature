import typedArrayConcat from '@vandeurenglenn/typed-array-concat'
import base58 from '@vandeurenglenn/base58'
import base32 from '@vandeurenglenn/base32'
import secp256k1 from 'secp256k1'
import varint from 'varint';

export default class MultiSignature {
	multiCodec: number
	version: number
	decoded: {
		version: number,
		multiCodec: number,
		signature: Uint8Array
	}
	encoded: Uint8Array

	#multiSignature: multiSignature

	constructor(version: number | undefined, multiCodec: number | undefined) {
		if (version === undefined) throw ReferenceError('version undefined');
		if (multiCodec === undefined) throw ReferenceError('multicodec undefined');
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

	sign(hash: Uint8Array, privateKey: Uint8Array): multiSignature {
		if (!hash || !privateKey)
			throw ReferenceError(`${hash ? 'privateKey' : 'hash'} undefined`);

		const {signature} = secp256k1.ecdsaSign(hash, privateKey);
		this.decoded = {
			version: this.version,
			multiCodec: this.multiCodec,
			signature
		};
		return this.encode(signature);
	}

	/**
   * verify signature (multiSignature.signature)
   */
	verifySignature(signature, hash, publicKey) {		
		return secp256k1.ecdsaVerify(signature, hash, publicKey);
	}

	/**
   * verify multiSignature
   */
	verify(multiSignature, hash, publicKey) {		
		multiSignature = this.decode(multiSignature);		
		return secp256k1.ecdsaVerify(multiSignature.signature, hash, publicKey)
	}

	encode(signature: Uint8Array): multiSignature {
		signature = signature || this.signature;
		if (!signature) throw ReferenceError('signature undefined');

		this.#multiSignature = typedArrayConcat([
			varint.encode(this.version),
			varint.encode(this.multiCodec),
			signature
		])
		return this.multiSignature;
	}

	/**
   * decode exported multi signature to object
   * @param {multiSignature} multiSignature base58 encoded string
   * @return {decodedMultiSignature} { version, multiCodec, signature }
   */
	decode(multiSignature: multiSignature): decodedMultiSignature {
		if (multiSignature) this.#multiSignature = multiSignature;
		if (!this.multiSignature) throw ReferenceError('multiSignature undefined');
		let buffer = this.multiSignature;
		const version = varint.decode(buffer);
		buffer = buffer.subarray(varint.decode.bytes)

		const codec = varint.decode(buffer);
		buffer = buffer.subarray(varint.decode.bytes)

		const signature = buffer.subarray(0, buffer.length);
		if (version !== this.version) throw TypeError('Invalid version');
		if (this.multiCodec !== codec) throw TypeError('Invalid multiCodec');

  	this.decoded = {
			version,
			multiCodec: codec,
			signature
		};
		return this.decoded;
	}

	toString() {
		return this.multiSignature.toString()
	}

	fromString(string) {
		return this.decode(new Uint8Array(string.split(',')))
	}

	toBs58() {
		return base58.encode(this.multiSignature)
	}

	fromBs58(string) {		
		return this.decode(base58.decode(string))
	}

	toBs32() {
		return base32.encode(this.multiSignature)
	}

	fromBs32(string: base32String) {
		return this.decode(base32.decode(string))
	}

	toBs32Hex() {
		return base32.encodeHex(this.multiSignature)
	}

	fromBs32Hex(string: base32HexString) {
		return this.decode(base32.decodeHex(string))
	}

	toBs58Hex() {
		return base58.encodeHex(this.multiSignature)
	}

	fromBs58Hex(string: base58HexString) {
		return this.decode(base58.decodeHex(string))
	}
}
