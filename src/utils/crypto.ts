import { decodeBase64Url } from "./encoding.ts";

export type KeyPairAlgorithm = "ec" | "rsa" | "rsa-4096";

export function getAlgorithmProperties(keyPairAlgorithm: KeyPairAlgorithm) {
  switch (keyPairAlgorithm){
    case "ec":
      return {
        name: "ECDSA",
        namedCurve: "P-256",
      };
    case "rsa":
      return {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: "SHA-256" },
      };
    case "rsa-4096":
      return {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 4096,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: "SHA-256" },
      };
  }
}

export async function generateKeyPair(keyPairAlgorithm: KeyPairAlgorithm = "ec"): Promise<CryptoKeyPair> {
  return await crypto.subtle.generateKey(
    getAlgorithmProperties(keyPairAlgorithm),
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
