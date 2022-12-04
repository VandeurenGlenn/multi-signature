import base58 from '@vandeurenglenn/base58'
import base32 from '@vandeurenglenn/base32'
import secp256k1 from 'secp256k1'
import varint from 'varint';

const {ecdsaSign, ecdsaVerify} = secp256k1

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

	set multiSignature(value) {
		this.#multiSignature = value;
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

		const {signature} = ecdsaSign(hash, privateKey);
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
		return ecdsaVerify(signature, hash, publicKey);
	}

	/**
   * verify multiSignature
   */
	verify(multiSignature, hash, publicKey) {
		multiSignature = this.decode(multiSignature);
		return ecdsaVerify(multiSignature.signature, hash, publicKey)
	}

	encode(signature: Uint8Array): multiSignature {
		signature = signature || this.signature;
		if (!signature) throw ReferenceError('signature undefined');
		const encodedVersion = varint.encode(this.version)
		const encodedCodec = varint.encode(this.multiCodec)
		const uint8Array = new Uint8Array(encodedVersion.length + encodedCodec.length + signature.length)

		uint8Array.set(encodedVersion)
		uint8Array.set(encodedCodec, encodedVersion.length)
		uint8Array.set(signature, encodedVersion.length + encodedCodec.length)
		this.multiSignature = uint8Array;
		return this.multiSignature;
	}

	/**
   * decode exported multi signature to object
   * @param {multiSignature} multiSignature base58 encoded string
   * @return {decodedMultiSignature} { version, multiCodec, signature }
   */
	decode(multiSignature: multiSignature): decodedMultiSignature {
		if (multiSignature) this.multiSignature = multiSignature;
		if (!this.multiSignature) throw ReferenceError('multiSignature undefined');
		let buffer = this.multiSignature;
		const version = varint.decode(buffer);
		buffer = buffer.slice(varint.decode.bytes)
		const codec = varint.decode(buffer);
		const signature = buffer.slice(varint.decode.bytes);
		if (version !== this.version) throw TypeError('Invalid version');
		if (this.multiCodec !== codec) throw TypeError('Invalid multiCodec');

  	this.decoded = {
			version,
			multiCodec: codec,
			signature
		};
		return this.decoded;
	}

	toHex() {
		return this.multiSignature.toString('hex')
	}

	fromHex(hex) {
		return base58.decode(hex)
	}

	toBs58() {
		return base58.encode(this.multiSignature)
	}

	fromBs58(multiSignature) {
		return base58.decode(multiSignature)
	}

	toBs32() {
		return base32.encode(this.multiSignature)
	}

	fromBs32(multiSignature) {
		return base32.decode(multiSignature)
	}
}
