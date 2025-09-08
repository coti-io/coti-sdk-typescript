export type itBool = {
    ciphertext: bigint
    signature: Uint8Array | string
}

export type itUint8 = {
    ciphertext: bigint
    signature: Uint8Array | string
}

export type itUint16 = {
    ciphertext: bigint
    signature: Uint8Array | string
}

export type itUint32 = {
    ciphertext: bigint
    signature: Uint8Array | string
}

export type itUint64 = {
    ciphertext: bigint
    signature: Uint8Array | string
}

export type itUint128 = {
    ciphertext: ctUint128
    signature: Uint8Array | string
}

export type itUint256 = {
    ciphertext: ctUint256
    signature: Uint8Array | string
}

export type itInt8 = {
    ciphertext: bigint
    signature: Uint8Array | string
}

export type itInt16 = {
    ciphertext: bigint
    signature: Uint8Array | string
}

export type itInt32 = {
    ciphertext: bigint
    signature: Uint8Array | string
}

export type itInt64 = {
    ciphertext: bigint
    signature: Uint8Array | string
}

export type itInt128 = {
    ciphertext: ctInt128
    signature: Uint8Array | string
}

export type itInt256 = {
    ciphertext: ctInt256
    signature: Uint8Array | string
}

export type itString = { ciphertext: { value: Array<bigint> }, signature: Array<Uint8Array | string> }

export type ctBool = bigint

export type ctUint8 = bigint

export type ctUint16 = bigint

export type ctUint32 = bigint

export type ctUint64 = bigint

export type ctUint128 = bigint

export type ctUint256 = {
    ciphertextHigh: ctUint128
    ciphertextLow: ctUint128
}

export type ctInt8 = bigint

export type ctInt16 = bigint

export type ctInt32 = bigint

export type ctInt64 = bigint

export type ctInt128 = bigint

export type ctInt256 = {
    ciphertextHigh: ctInt128
    ciphertextLow: ctInt128
}

export type ctString = { value: Array<bigint> }

// Types for the new crypto library constants
export type CryptoConstants = {
    BLOCK_SIZE: number
    ADDRESS_SIZE: number
    FUNC_SIG_SIZE: number
    CT_SIZE: number
    KEY_SIZE: number
    HEX_BASE: number
    EIGHT_BYTES: number
    MAX_PLAINTEXT_BIT_SIZE: number
}