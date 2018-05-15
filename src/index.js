import hmac from 'crypto-js/hmac-sha3';
import { encode, decode } from 'bs58';
import RIPEMD160 from 'ripemd160';

export default class MultiSignature {
	constructor(version, multiCodec) {
		if (version === undefined) throw ReferenceError('version undefined');
		if (multiCodec === undefined) throw ReferenceError('multicodec undefined');
		this.version = version;
		this.multiCodec = multiCodec;
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

	sign(hash, address) {
		if (!hash || !address)
			throw ReferenceError(`${hash ? 'address' : 'hash'} undefined`);
    else if (typeof hash !== 'string')
      throw TypeError(`${Boolean(typeof hash === 'string') ? 'address' : 'hash'} is not a typeof string`);

		let signature = hmac(hash, address, 256).toString();
    signature = new RIPEMD160().update(signature).digest();
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
	verifySignature(signature, hash, address) {
		return Boolean(signature === hmac(hash, address).toString());
	}

	/**
   * verify multiSignature
   */
	verify(multiSignature, hash, address) {
		return Boolean(multiSignature === this.sign(hash, address));
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
			Buffer.from(this.version.toString()),
			Buffer.from(this.multiCodec.toString()),
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
		const buffer = decode(this.multiSignature);
		const version = parseInt(buffer.slice(0, 1));
		const codec = parseInt(buffer.slice(1, 5));
		const signature = buffer.slice(5, buffer.length);
		if (version !== this.version) throw TypeError('Invalid version');
		if (this.multiCodec !== codec) throw TypeError('Invalid multiCodec');
  	this.decoded = {
			version,
			multiCodec,
			signature
		};
		return this.decoded;
	}
}
