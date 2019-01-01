import { encode, decode } from 'bs58';
import ecc from 'tiny-secp256k1';
import varint from 'varint';

export default class MultiSignature {
	constructor(version, multiCodec) {
		if (version === undefined) throw ReferenceError('version undefined');
		if (multiCodec === undefined) throw ReferenceError('multicodec undefined');
		this.multiCodec = multiCodec;
		this.version = version;
	}

	set multiSignature(value) {
		this._multiSignature = value;
	}

	get signature() {
		return this.decoded.signature;
	}

	get multiSignature() {
		return this._multiSignature || this.encoded || this.encode(this.signature);
	}

	export() {
		return this.multiSignature;
	}

	import(encoded) {
		return this.decode(encoded);
	}

	sign(hash, privateKey) {
		if (!hash || !privateKey)
			throw ReferenceError(`${hash ? 'privateKey' : 'hash'} undefined`);

		const signature = ecc.sign(hash, privateKey);

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
		return ecc.verify(hash, publicKey, signature);
	}

	/**
   * verify multiSignature
   */
	verify(multiSignature, hash, publicKey) {
		multiSignature = this.decode(multiSignature);
		return ecc.verify(hash, publicKey, multiSignature.signature)
		// return Boolean(multiSignature === this.sign(hash, publicKey));
	}

	/**
   * encode multi signature to exportable format
   * @param {buffer} signature base58 encoded string
   * @return {object} base58 encoded multiSignature
   */
	encode(signature) {
		signature = signature || this.signature;
		if (!signature) throw ReferenceError('signature undefined');
		const buffer = Buffer.concat([
			Buffer.from(varint.encode(this.version)),
			Buffer.from(varint.encode(this.multiCodec)),
			signature
		]);
		this.multiSignature = encode(buffer);
		return this.multiSignature;
	}

	/**
   * decode exported multi signature to object
   * @param {string} multiSignature base58 encoded string
   * @return {object} { version, multiCodec, signature }
   */
	decode(multiSignature) {
		if (multiSignature) this.multiSignature = multiSignature;
		if (!this.multiSignature) throw ReferenceError('multiSignature undefined');
		let buffer = decode(this.multiSignature);
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
}
