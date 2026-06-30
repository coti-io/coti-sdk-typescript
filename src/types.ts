export type itBool = {
    ciphertext: bigint
    signature: Uint8Array | string
}

export type itUint = {
    ciphertext: bigint
    signature: Uint8Array | string
}

export type itString = { ciphertext: { value: Array<bigint> }, signature: Array<Uint8Array | string> }

export type ctBool = bigint

/**
 * On-chain encrypted integer (COTI ctUint64).
 *
 * Stored as a single `bigint` packing **32 bytes**: a 16-byte AES ciphertext
 * followed by a 16-byte random `r`. Plaintext bit width depends on the API:
 *
 * - {@link encryptUint} / {@link decryptUint} / {@link buildInputText}: up to **64-bit** plaintext
 * - {@link prepareIT}: up to **128-bit** plaintext (same 32-byte wire format)
 *
 * The type name `ctUint` reflects the on-chain ctUint64 type; do not assume the
 * bigint's magnitude equals the plaintext — it encodes the full ciphertext blob.
 */
export type ctUint = bigint

/** String ciphertext: an array of {@link ctUint} chunks (8-byte UTF-8 segments). */
export type ctString = { value: Array<bigint> }

export type SerializableCtUint = string | number | bigint


export type itUint256 = {
    ciphertext: { ciphertextHigh: bigint; ciphertextLow: bigint };
    signature: Uint8Array;
  };

export type ctUint256 = {
    ciphertextHigh: bigint;
    ciphertextLow: bigint;
  };

export type ctUint256Nested = {
    high: { high: bigint; low: bigint };
    low: { high: bigint; low: bigint };
  };

export type CtUint256Like =
    | ctUint256
    | ctUint256Nested
    | [SerializableCtUint, SerializableCtUint];

export type itUint256Signed = {
    ciphertext: ctUint256;
    signature: string;
  };

export type BuildItUint256WithSignerParams = {
    value: bigint;
    aesKey: string;
    signerAddress: string;
    contractAddress: string;
    functionSelector: string;
    signMessage: (message: Uint8Array) => string | Promise<string>;
  };

export type SerializableCtUint256 =
    | {
        ciphertextHigh?: SerializableCtUint;
        ciphertextLow?: SerializableCtUint;
      }
    | [SerializableCtUint, SerializableCtUint];