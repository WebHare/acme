import { decodeBase64Url } from "./encoding.ts";

export async function generateKeyPair(): Promise<CryptoKeyPair> {
  return await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
}

export async function importHmacKey(hmacKey: string): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    "raw",
    decodeBase64Url(hmacKey),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

export async function sign(
  key: CryptoKey,
  data: Uint8Array,
): Promise<Uint8Array> {
  const signature = await crypto.subtle.sign(
    {
      name: key.algorithm.name,
      hash: "SHA-256",
    },
    key,
    data,
  );
  return new Uint8Array(signature);
}
