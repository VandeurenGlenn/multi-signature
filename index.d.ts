declare type multiSignature = Uint8Array
declare type decodedMultiSignature = {
  version: number,
  multiCodec: number,
  signature: Uint8Array
}

declare class MultiSignatureInterface {
  multiCodec: number
  version: number
  decoded: decodedMultiSignature
  encoded: Uint8Array

  #multiSignature: multiSignature
}

declare module 'multi-signature' {
  export default MultiSignatureInterface
}