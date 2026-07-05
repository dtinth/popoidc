// Generate an RSA signing key as a private JWK for SSHID_SIGNING_JWK.
//   deno task keygen
import { exportJWK, generateKeyPair } from "jose";

const { privateKey } = await generateKeyPair("RS256", { extractable: true });
const jwk = {
  ...(await exportJWK(privateKey)),
  kid: new Date().toISOString().slice(0, 10),
  alg: "RS256",
  use: "sig",
};
console.log(JSON.stringify(jwk));
