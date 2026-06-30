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

export type ctUint = bigint

export type ctString = { value: Array<bigint> }


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

export type SerializableCtUint = string | number | bigint

export type SerializableCtUint256 = {
    ciphertextHigh?: string | number | bigint;
    ciphertextLow?: string | number | bigint;
  };