import { Wallet, recoverAddress, solidityPackedKeccak256, getBytes, hexlify } from 'ethers'
import {
    buildInputText,
    buildItSignature,
    decryptCtUint64,
    isInsaneDecryptedValue,
    normalizeAesKey,
    signInputText,
    validateAesKey
} from '../../src'

const AES_KEY = '0123456789abcdef0123456789abcdef' // 32 hex chars (128-bit)
const AES_KEY_256 = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' // 64 hex chars
const CONTRACT_ADDRESS = '0x0000000000000000000000000000000000000001'
const FUNCTION_SELECTOR = '0x11223344'

describe('normalizeAesKey', () => {
    test('strips the 0x prefix', () => {
        expect(normalizeAesKey('0x' + AES_KEY)).toBe(AES_KEY)
    })

    test('lowercases the key', () => {
        expect(normalizeAesKey(AES_KEY.toUpperCase())).toBe(AES_KEY)
    })

    test('accepts a 32-char (128-bit) key', () => {
        expect(normalizeAesKey(AES_KEY)).toBe(AES_KEY)
    })

    test('accepts a 64-char (256-bit) key', () => {
        expect(normalizeAesKey(AES_KEY_256)).toBe(AES_KEY_256)
    })

    test('throws on non-hexadecimal characters', () => {
        expect(() => normalizeAesKey('g'.repeat(32))).toThrow('non-hexadecimal')
    })

    test('throws on invalid length', () => {
        expect(() => normalizeAesKey('abcdef')).toThrow('expected 32 or 64 hex characters')
    })
})

describe('validateAesKey', () => {
    test('throws when key is undefined', () => {
        expect(() => validateAesKey(undefined)).toThrow('AES key is required')
    })

    test('throws when key is null', () => {
        expect(() => validateAesKey(null)).toThrow('AES key is required')
    })

    test('throws when key is an empty string', () => {
        expect(() => validateAesKey('')).toThrow('AES key is required')
    })

    test('returns the normalized key when valid', () => {
        expect(validateAesKey('0x' + AES_KEY.toUpperCase())).toBe(AES_KEY)
    })

    test('propagates normalizeAesKey validation errors', () => {
        expect(() => validateAesKey('zz')).toThrow('non-hexadecimal')
    })
})

describe('isInsaneDecryptedValue', () => {
    test('returns false for a value equal to the default threshold', () => {
        // default base = 1e12, default decimals = 18 => threshold = 10^30
        expect(isInsaneDecryptedValue(10n ** 30n)).toBe(false)
    })

    test('returns true for a value above the default threshold', () => {
        expect(isInsaneDecryptedValue(10n ** 30n + 1n)).toBe(true)
    })

    test('honors a custom thresholdBase', () => {
        // base = 100, decimals = 0 => threshold = 100
        expect(isInsaneDecryptedValue(101n, 0, 100n)).toBe(true)
        expect(isInsaneDecryptedValue(100n, 0, 100n)).toBe(false)
    })

    test('clamps negative decimals to 0', () => {
        // decimals clamped to 0 => threshold = 1 * 10^0 = 1
        expect(isInsaneDecryptedValue(2n, -5, 1n)).toBe(true)
        expect(isInsaneDecryptedValue(1n, -5, 1n)).toBe(false)
    })

    test('clamps decimals above 36', () => {
        // decimals clamped to 36 => threshold = 1 * 10^36
        expect(isInsaneDecryptedValue(10n ** 36n, 40, 1n)).toBe(false)
        expect(isInsaneDecryptedValue(10n ** 36n + 1n, 40, 1n)).toBe(true)
    })

    test('falls back to 18 decimals for non-finite input', () => {
        // decimals NaN => 18 => threshold = 1 * 10^18
        expect(isInsaneDecryptedValue(10n ** 18n, NaN, 1n)).toBe(false)
        expect(isInsaneDecryptedValue(10n ** 18n + 1n, NaN, 1n)).toBe(true)
    })
})

describe('decryptCtUint64', () => {
    function buildCiphertext(plaintext: bigint): bigint {
        const wallet = Wallet.createRandom()
        const { ciphertext } = buildInputText(
            plaintext,
            { wallet, userKey: AES_KEY },
            CONTRACT_ADDRESS,
            FUNCTION_SELECTOR
        )
        return ciphertext
    }

    test('returns 0n for a zero ciphertext without touching the key', () => {
        expect(decryptCtUint64(0n, 'not-a-valid-key')).toBe(0n)
    })

    test('round-trips a small plaintext value', () => {
        const ciphertext = buildCiphertext(12345n)
        expect(decryptCtUint64(ciphertext, AES_KEY)).toBe(12345n)
    })

    test('accepts a 0x-prefixed key', () => {
        const ciphertext = buildCiphertext(777n)
        expect(decryptCtUint64(ciphertext, '0x' + AES_KEY)).toBe(777n)
    })

    test('returns null on an invalid key', () => {
        const ciphertext = buildCiphertext(42n)
        expect(decryptCtUint64(ciphertext, 'xyz')).toBeNull()
    })

    test('returns null when the value exceeds the sanity threshold', () => {
        const ciphertext = buildCiphertext(12345n)
        // force the threshold low enough that the decrypted value is "insane"
        expect(decryptCtUint64(ciphertext, AES_KEY, { decimals: 0, insaneThresholdBase: 1n })).toBeNull()
    })
})

describe('buildItSignature', () => {
    test('produces a 65-byte hex signature', () => {
        const wallet = Wallet.createRandom()
        const signature = buildItSignature(
            wallet.address,
            CONTRACT_ADDRESS,
            FUNCTION_SELECTOR,
            12345n,
            wallet.privateKey
        )
        expect(typeof signature).toBe('string')
        // 0x + 65 bytes * 2 hex chars = 132 characters
        expect(signature.length).toBe(132)
    })

    test('recovers the correct signer address', () => {
        const wallet = Wallet.createRandom()
        const ciphertext = 12345n
        const signature = buildItSignature(
            wallet.address,
            CONTRACT_ADDRESS,
            FUNCTION_SELECTOR,
            ciphertext,
            wallet.privateKey
        )

        const digest = solidityPackedKeccak256(
            ['address', 'address', 'bytes4', 'uint256'],
            [wallet.address, CONTRACT_ADDRESS, FUNCTION_SELECTOR, ciphertext]
        )

        const bytes = getBytes(signature)
        const r = hexlify(bytes.slice(0, 32))
        const s = hexlify(bytes.slice(32, 64))
        const v = bytes[64] + 27

        const recovered = recoverAddress(digest, { r, s, v })
        expect(recovered.toLowerCase()).toBe(wallet.address.toLowerCase())
    })

    test('matches the bytes produced by signInputText for the same inputs', () => {
        const wallet = Wallet.createRandom()
        const ciphertext = 98765n

        const fromBuild = buildItSignature(
            wallet.address,
            CONTRACT_ADDRESS,
            FUNCTION_SELECTOR,
            ciphertext,
            wallet.privateKey
        )

        const fromSignInputText = hexlify(
            signInputText(
                { wallet, userKey: '' },
                CONTRACT_ADDRESS,
                FUNCTION_SELECTOR,
                ciphertext
            )
        )

        expect(fromBuild).toBe(fromSignInputText)
    })
})
