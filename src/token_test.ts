import { assert, assertEquals } from "@std/assert";
import { createLocalJWKSet, jwtVerify } from "jose";
import { discoveryDocument, jwksDocument, mintToken } from "./token.ts";
import { testSigningKey } from "./testutil.ts";

Deno.test("mintToken issues an RS256 JWT that verifies against the JWKS", async () => {
  const sk = await testSigningKey("kid-a");
  const iat = 1_700_000_000;
  const token = await mintToken({
    issuer: "https://sshid.example",
    subject: "SHA256:abc",
    audience: "octo-sts.dev",
    key: "ssh-ed25519 AAAAC3Nz",
    keyType: "ssh-ed25519",
    signingKey: sk,
    nowSeconds: iat,
  });

  const jwks = createLocalJWKSet(jwksDocument([sk]));
  const { payload, protectedHeader } = await jwtVerify(token, jwks, {
    issuer: "https://sshid.example",
    audience: "octo-sts.dev",
    currentDate: new Date((iat + 1) * 1000),
  });

  assertEquals(protectedHeader.alg, "RS256");
  assertEquals(protectedHeader.kid, "kid-a");
  assertEquals(payload.sub, "SHA256:abc");
  assertEquals(payload.key, "ssh-ed25519 AAAAC3Nz");
  assertEquals(payload.key_type, "ssh-ed25519");
  assertEquals(payload.iat, iat);
  assertEquals(payload.exp, iat + 900);
  assert(typeof payload.jti === "string" && payload.jti.length > 0);
});

Deno.test("discoveryDocument advertises issuer, jwks_uri and RS256", () => {
  const d = discoveryDocument("https://sshid.example");
  assertEquals(d.issuer, "https://sshid.example");
  assertEquals(d.jwks_uri, "https://sshid.example/.well-known/jwks.json");
  assertEquals(d.id_token_signing_alg_values_supported, ["RS256"]);
});

Deno.test("jwksDocument exposes public keys with kid+alg and no private component", async () => {
  const sk = await testSigningKey("kid-b");
  const doc = jwksDocument([sk]);
  assertEquals(doc.keys.length, 1);
  assertEquals(doc.keys[0].kid, "kid-b");
  assertEquals(doc.keys[0].alg, "RS256");
  assertEquals(doc.keys[0].kty, "RSA");
  assert(doc.keys[0].d === undefined, "private exponent must not be exposed");
});
