import { Wallet } from 'ethers'
import {
    encodeUint,
    decodeUint,
    encodeKey,
    encrypt,
    decrypt,
    prepareIT,
    prepareIT256,
    decryptUint,
    decryptUint256
} from '../../src'

// Load test constants from environment variables
const TEST_CONSTANTS = {
    PRIVATE_KEY: process.env.TEST_PRIVATE_KEY || '',
    USER_KEY: process.env.TEST_USER_KEY || '',
    CONTRACT_ADDRESS: '0x0000000000000000000000000000000000000001',
    FUNCTION_SELECTOR: '0x11223344'
}

const HAS_ENV = !!(TEST_CONSTANTS.PRIVATE_KEY && TEST_CONSTANTS.USER_KEY)

function createTestSender() {
    return {
        wallet: new Wallet(TEST_CONSTANTS.PRIVATE_KEY),
        userKey: TEST_CONSTANTS.USER_KEY
    }
}

/**
 * Generates a random BigInt within the specified bit range.
 * Uses Math.random for test-quality randomness (not cryptographic).
 */
function randomBigInt(maxBits: number): bigint {
    const bits = Math.floor(Math.random() * maxBits) + 1 // NOSONAR: intentionally non-cryptographic, used only for test data generation
    let result = 0n
    for (let i = 0; i < bits; i += 32) {
        const chunk = BigInt(Math.floor(Math.random() * 0xFFFFFFFF)) // NOSONAR
        result = (result << 32n) | chunk
    }
    // Mask to the desired bit size
    const mask = (1n << BigInt(bits)) - 1n
    return result & mask
}

/**
 * Generates a random 32-character hex string (16 bytes).
 */
function randomHexKey(): string {
    const chars = '0123456789abcdef'
    let key = ''
    for (let i = 0; i < 32; i++) {
        key += chars[Math.floor(Math.random() * chars.length)] // NOSONAR
    }
    return key
}

/**
 * Property-based tests that verify round-trip invariants across
 * randomized inputs. These address TESTS.md recommendation #4:
 * "Property-based round-trip tests for encodeUint/decodeUint"
 */
const describeWithEnv = HAS_ENV ? describe : describe.skip
describeWithEnv('Unit: Property-Based Round-Trip Tests', () => {

    describe('encodeUint / decodeUint invertibility', () => {
        // Test with 50 random BigInts to verify: decodeUint(encodeUint(x)) === x
        const NUM_ITERATIONS = 50
        const testValues: bigint[] = []
        for (let i = 0; i < NUM_ITERATIONS; i++) {
            testValues.push(randomBigInt(128))
        }

        test.each(testValues.map((v, i) => [i, v]))(
            'round-trip #%d: decodeUint(encodeUint(x)) === x',
            (_index, value) => {
                const v = value as bigint
                const encoded = encodeUint(v)
                const decoded = decodeUint(encoded)
                expect(decoded).toEqual(v)
            }
        )

        test('round-trip with zero', () => {
            const encoded = encodeUint(0n)
            const decoded = decodeUint(encoded)
            expect(decoded).toEqual(0n)
        })

        test('round-trip with max 128-bit value', () => {
            const maxValue = (2n ** 128n) - 1n
            const encoded = encodeUint(maxValue)
            const decoded = decodeUint(encoded)
            expect(decoded).toEqual(maxValue)
        })

        test('encodeUint always produces 16-byte output', () => {
            const values = [0n, 1n, 255n, 65535n, (2n ** 64n) - 1n, (2n ** 128n) - 1n]
            for (const v of values) {
                const encoded = encodeUint(v)
                expect(encoded.length).toBe(16)
            }
        })
    })

    describe('encodeKey consistency', () => {
        test('encodeKey is idempotent for the same input', () => {
            const keys = [
                '00000000000000000000000000000000',
                'ffffffffffffffffffffffffffffffff',
                '0123456789abcdef0123456789abcdef',
                TEST_CONSTANTS.USER_KEY,
            ]
            for (const key of keys) {
                const result1 = encodeKey(key)
                const result2 = encodeKey(key)
                expect(result1).toEqual(result2)
                expect(result1.length).toBe(16)
            }
        })

        test('encodeKey produces different output for different keys', () => {
            const key1 = randomHexKey()
            let key2 = randomHexKey()
            // Make sure they're different
            while (key1 === key2) key2 = randomHexKey()

            const encoded1 = encodeKey(key1)
            const encoded2 = encodeKey(key2)
            expect(encoded1).not.toEqual(encoded2)
        })

        test('encodeKey with all-zeros produces zero array', () => {
            const zeroKey = '00000000000000000000000000000000'
            const encoded = encodeKey(zeroKey)
            expect(encoded.every(byte => byte === 0)).toBe(true)
        })

        test('encodeKey with all-ff produces 255 array', () => {
            const ffKey = 'ffffffffffffffffffffffffffffffff'
            const encoded = encodeKey(ffKey)
            expect(encoded.every(byte => byte === 255)).toBe(true)
        })
    })

    describe('encrypt / decrypt invertibility with random keys', () => {
        test('encrypt then decrypt round-trip with generated AES key', () => {
            // Use the known test key for deterministic behavior
            const keyBytes = encodeKey(TEST_CONSTANTS.USER_KEY)

            const testPlaintexts = [
                new Uint8Array(16), // all zeros
                new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 57]),
                new Uint8Array([255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]),
            ]

            for (const plaintext of testPlaintexts) {
                const { ciphertext, r } = encrypt(keyBytes, plaintext)
                const decrypted = decrypt(keyBytes, r, ciphertext)
                expect(decrypted).toEqual(plaintext)
            }
        })
    })

    describe('prepareIT / decryptUint full-cycle with random values', () => {
        const NUM_ITERATIONS = 10
        const testValues: bigint[] = []
        for (let i = 0; i < NUM_ITERATIONS; i++) {
            testValues.push(randomBigInt(128))
        }

        test.each(testValues.map((v, i) => [i, v]))(
            'full-cycle round-trip #%d: decryptUint(prepareIT(x)) === x',
            (_index, value) => {
                const v = value as bigint
                const { ciphertext } = prepareIT(
                    v,
                    createTestSender(),
                    TEST_CONSTANTS.CONTRACT_ADDRESS,
                    TEST_CONSTANTS.FUNCTION_SELECTOR
                )
                const decrypted = decryptUint(ciphertext, TEST_CONSTANTS.USER_KEY)
                expect(decrypted).toEqual(v)
            }
        )
    })

    describe('prepareIT256 / decryptUint256 full-cycle with random values', () => {
        const NUM_ITERATIONS = 5
        const testValues: bigint[] = []
        for (let i = 0; i < NUM_ITERATIONS; i++) {
            testValues.push(randomBigInt(256))
        }

        test.each(testValues.map((v, i) => [i, v]))(
            'full-cycle round-trip #%d: decryptUint256(prepareIT256(x)) === x',
            (_index, value) => {
                const v = value as bigint
                const { ciphertext } = prepareIT256(
                    v,
                    createTestSender(),
                    TEST_CONSTANTS.CONTRACT_ADDRESS,
                    TEST_CONSTANTS.FUNCTION_SELECTOR
                )
                const decrypted = decryptUint256(ciphertext, TEST_CONSTANTS.USER_KEY)
                expect(decrypted).toEqual(v)
            }
        )
    })
})
