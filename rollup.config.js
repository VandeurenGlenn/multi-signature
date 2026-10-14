import typescript from "@rollup/plugin-typescript";

export default [
  {
    input: ["src/index.ts"],
    external: ['@noble/secp256k1', '@vandeurenglenn/base58', '@vandeurenglenn/base32', '@leofcoin/codecs/binary', 'crypto'],
    output: {
      dir: "./",
      format: "es",
      sourcemap: false,
    },
    plugins: [typescript()],
  },
];
