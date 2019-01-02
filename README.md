# multi-signature
> Identifiable signatures <version><codec><signature>

## install
### npm
```sh
npm i multi-signature --save
```
### yarn
```sh
yarn add multi-signature
```

## usage
```js
import MultiSignature from 'multi-signature';
const multi = new MultiSignature(<version>, <codec>);
const signature = multi.sign(<data>, <key>); // base58 encoded MultiSignature
const data = 'some data';
const key = '1234';
const version = 0x00;
const codec = 0x01;

const multi2 = new MultiSignature(version, codec);
multi2.verify(signature, data, key); // returns boolean

const raw = multi2.signature; // raw signature
multi2.verifySignature(raw, data, key); // returns boolean

multi2.multiSignature; // base58 encoded MultiSignature
multi2.decoded // { version, codec, signature }
```
## use case
Future proof cryptocurrency signatures (signatures are versioned & each version should be supported (with exceptions)).
In short:
- disables the need for a "fork" when changing signature behaviour.
- nodes that aren't updated can (atleast for some time) contribute to the network by handling other not updated nodes their transactions.
- updated nodes can still handle older nodes their transactions (until some point in time or whenever an vulnerability is found.)
- flag vulnerable versions by sending a flag Message (flags are send to every node & accepted only when 3/4 off total nodes agree, this results into an lockdown off the flagged node, all other nodes will ignore it until the flagged has updated to the needed version).

## API

### sign
##### hash
`description`: data to sign<br>
`type`: buffer
##### key
`description`: privateKey<br>
`type`: buffer<br>

```js
new MultiSignature(version, codec).sign(data, key)
```

### verify
##### multiSignature
`description`: multiSignature to verify<br>
`type`: string (MultiSignature encoded)<br>
##### hash
`description`: data to verify<br>
`type`: buffer<br>
##### key
`description`: publicKey<br>
`type`: buffer<br>

```js
new MultiSignature(version, codec).verify(multiSignature, data, key)
```

### verifySignature
##### signature
`description`: signature to verify<br>
`type`: buffer<br>
##### hash
`description`: data to verify<br>
`type`: buffer<br>
##### key
`description`: publicKey<br>
`type`: buffer<br>

```js
new MultiSignature(version, codec).verifySignature(signature, data, key)
```

### decode
##### multiSignature
`description`: multiSignature to decode<br>
`type`: string (MultiSignature encoded)<br>

```js
new MultiSignature(version, codec).decode(multiSignature)
```

### encode
##### signature
`description`: signature<br>
`type`: buffer<br>

```js
new MultiSignature(version, codec).encode(signature)
```

## LICENSE
Copyright (c) 2018 vandeurenglenn
