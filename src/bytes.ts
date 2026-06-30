import { ctUint256 } from './types'

/** Radix used for hex encoding/decoding in this module. */
export const HEX_BASE = 16

/** Byte length of a single {@link ctUint} on the wire (ciphertext + random `r`). */
export const CT_SIZE = 32

/**
 * Encodes an unsigned bigint as a fixed-width big-endian byte array.
 *
 * @param value - Integer to encode.
 * @param width - Output length in bytes; leading zero bytes are emitted as needed.
 * @returns Big-endian bytes of length `width`.
 */
export function bigintToBytesBE(value: bigint, width: number): Uint8Array {
    const bytes = new Uint8Array(width)
    for (let i = width - 1; i >= 0; i--) {
        bytes[i] = Number(value & BigInt(0xff))
        value >>= BigInt(8)
    }
    return bytes
}

/**
 * Decodes a big-endian byte array into an unsigned bigint.
 *
 * @param bytes - Non-empty byte array to decode.
 * @returns Unsigned integer represented by `bytes`.
 * @throws SyntaxError if `bytes` is empty.
 */
export function bytesToBigint(bytes: Uint8Array): bigint {
    return BigInt("0x" + bytesToHex(bytes))
}

/**
 * Encodes bytes as a lowercase hex string (two digits per byte).
 *
 * @param bytes - Byte array to encode.
 * @returns Hex string without `0x` prefix.
 */
export function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map(byte => byte.toString(HEX_BASE).padStart(2, '0'))
        .join('')
}

/**
 * Serializes a {@link ctUint} bigint to its 32-byte on-wire representation.
 *
 * @param ciphertext - ctUint value as a bigint.
 * @returns 32-byte big-endian blob ({@link CT_SIZE} bytes).
 */
export function ctUintToBytes(ciphertext: bigint): Uint8Array {
    return bigintToBytesBE(ciphertext, CT_SIZE)
}

/**
 * Serializes a {@link ctUint256} to a 64-byte concatenation of its two ctUint limbs.
 *
 * @param ciphertext - ctUint256 with `ciphertextHigh` and `ciphertextLow`.
 * @returns 64-byte buffer: high limb (32 B) followed by low limb (32 B).
 */
export function ctUint256ToBytes(ciphertext: ctUint256): Uint8Array {
    return new Uint8Array([
        ...ctUintToBytes(ciphertext.ciphertextHigh),
        ...ctUintToBytes(ciphertext.ciphertextLow)
    ])
}

/**
 * Parses a 64-byte ciphertext blob into a {@link ctUint256} object.
 *
 * @param ciphertext - 64-byte buffer (typically from encryption helpers).
 * @returns ctUint256 with `ciphertextHigh` and `ciphertextLow` bigints.
 */
export function ciphertextBytesToCtUint256(ciphertext: Uint8Array): ctUint256 {
    return {
        ciphertextHigh: bytesToBigint(ciphertext.slice(0, CT_SIZE)),
        ciphertextLow: bytesToBigint(ciphertext.slice(CT_SIZE))
    }
}
