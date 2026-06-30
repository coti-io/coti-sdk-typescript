import { ctUint256 } from './types'

export const HEX_BASE = 16
export const CT_SIZE = 32

export function bigintToBytesBE(value: bigint, width: number): Uint8Array {
    const bytes = new Uint8Array(width)
    for (let i = width - 1; i >= 0; i--) {
        bytes[i] = Number(value & BigInt(0xff))
        value >>= BigInt(8)
    }
    return bytes
}

export function bytesToBigint(bytes: Uint8Array): bigint {
    return BigInt("0x" + bytesToHex(bytes))
}

export function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map(byte => byte.toString(HEX_BASE).padStart(2, '0'))
        .join('')
}

export function ctUintToBytes(ciphertext: bigint): Uint8Array {
    return bigintToBytesBE(ciphertext, CT_SIZE)
}

export function ctUint256ToBytes(ciphertext: ctUint256): Uint8Array {
    return new Uint8Array([
        ...ctUintToBytes(ciphertext.ciphertextHigh),
        ...ctUintToBytes(ciphertext.ciphertextLow)
    ])
}

export function ciphertextBytesToCtUint256(ciphertext: Uint8Array): ctUint256 {
    return {
        ciphertextHigh: bytesToBigint(ciphertext.slice(0, CT_SIZE)),
        ciphertextLow: bytesToBigint(ciphertext.slice(CT_SIZE))
    }
}
