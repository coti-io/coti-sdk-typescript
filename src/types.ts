/** Signed input text for a boolean value (ctBool ciphertext + signature). */
export type itBool = {
    ciphertext: bigint
    signature: Uint8Array | string
}

/** Signed input text for an unsigned integer ({@link ctUint} ciphertext + signature). */
export type itUint = {
    ciphertext: bigint
    signature: Uint8Array | string
}

/** Signed input text for a UTF-8 string (one {@link ctUint} chunk + signature per 8-byte segment). */
export type itString = { ciphertext: { value: Array<bigint> }, signature: Array<Uint8Array | string> }

/** On-chain encrypted boolean (stored as ctUint64-compatible bigint). */
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

/** JSON/RPC-serializable scalar that coerces to {@link ctUint}. */
export type SerializableCtUint = string | number | bigint

/** Signed 256-bit input text for smart contract submission (private-key path). */
export type itUint256 = {
    ciphertext: { ciphertextHigh: bigint; ciphertextLow: bigint };
    signature: Uint8Array;
  };

/** Canonical on-chain 256-bit ciphertext (two ctUint64 limbs). */
export type ctUint256 = {
    ciphertextHigh: bigint;
    ciphertextLow: bigint;
  };

/** Nested on-chain ctUint256 wire format (four ctUint64 limbs). */
export type ctUint256Nested = {
    high: { high: bigint; low: bigint };
    low: { high: bigint; low: bigint };
  };

/** Any ctUint256 shape accepted by {@link isCtUint256Shape} and {@link decryptCtUint256}. */
export type CtUint256Like =
    | ctUint256
    | ctUint256Nested
    | [SerializableCtUint, SerializableCtUint];

/** Signed 256-bit input text returned by {@link buildItUint256WithSigner} (browser-wallet path). */
export type itUint256Signed = {
    ciphertext: ctUint256;
    signature: string;
  };

/** Parameters for {@link buildItUint256WithSigner}. */
export type BuildItUint256WithSignerParams = {
    /** Plaintext value to encrypt (up to 256 bits). */
    value: bigint;
    /** User AES key (32 hex chars, optionally `0x`-prefixed). */
    aesKey: string;
    /** Address of the external wallet signer. */
    signerAddress: string;
    /** Target contract address. */
    contractAddress: string;
    /** 4-byte function selector (e.g. `"0x11223344"`). */
    functionSelector: string;
    /** Wallet callback that signs the ABI-packed message bytes. */
    signMessage: (message: Uint8Array) => string | Promise<string>;
  };

/** JSON/RPC-serializable payload that coerces to {@link ctUint256} via {@link normalizeCtPayload}. */
export type SerializableCtUint256 =
    | {
        ciphertextHigh?: SerializableCtUint;
        ciphertextLow?: SerializableCtUint;
      }
    | [SerializableCtUint, SerializableCtUint];
