import { createHash, createHmac } from "crypto";
import * as secp256k1 from "@noble/secp256k1";

// Register Node.js SHA-256 for @noble/secp256k1
secp256k1.utils.hmacSha256Sync = (key, ...msgs) => {
  const hmac = createHmac("sha256", key);
  for (const msg of msgs) hmac.update(msg);
  return new Uint8Array(hmac.digest());
};
secp256k1.utils.sha256Sync = (msg) => {
  return new Uint8Array(createHash("sha256").update(msg).digest());
};

export { secp256k1 };
