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
    signature: [Uint8Array | string, Uint8Array | string]
}

export type itUint256 = {
    ciphertext: ctUint256
    signature: [[Uint8Array | string, Uint8Array | string], [Uint8Array | string, Uint8Array | string]]
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
    signature: [Uint8Array | string, Uint8Array | string]
}

export type itInt256 = {
    ciphertext: ctInt256
    signature: [[Uint8Array | string, Uint8Array | string], [Uint8Array | string, Uint8Array | string]]
}

export type itString = { ciphertext: { value: Array<bigint> }, signature: Array<Uint8Array | string> }

export type ctBool = bigint

export type ctUint8 = bigint

export type ctUint16 = bigint

export type ctUint32 = bigint

export type ctUint64 = bigint

export type ctUint128 = {
    high: bigint
    low: bigint
}

export type ctUint256 = {
    high: ctUint128
    low: ctUint128
}

export type ctInt8 = bigint

export type ctInt16 = bigint

export type ctInt32 = bigint

export type ctInt64 = bigint

export type ctInt128 = {
    high: bigint
    low: bigint
}

export type ctInt256 = {
    high: ctInt128
    low: ctInt128
}

export type ctString = { value: Array<bigint> }