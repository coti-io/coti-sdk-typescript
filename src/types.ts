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