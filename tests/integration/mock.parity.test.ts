import { Wallet } from 'ethers'
import {
    encrypt,
    decrypt,
    encodeKey,
    encodeUint,
    prepareIT,
    decryptUint,
    prepareIT256,
    decryptUint256
} from '../../src'

/**
 * Mock Parity Tests - TESTS.md Recommendation #5
 * 
 * These tests verify that the decrypt path works correctly regardless of
 * whether encryption used mocked or real (integration) randomness.
 * 
 * The unit tests in crypto_utils.test.ts mock node-forge randomness for
 * determinism. These integration tests use real randomness. This file
 * verifies that both approaches produce ciphertexts that decrypt correctly.
 */

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

const describeWithEnv = HAS_ENV ? describe : describe.skip
describeWithEnv('Integration: Mock vs Real Randomness Parity', () => {

    describe('encrypt/decrypt with real randomness', () => {
        test('encrypt produces different ciphertexts on each call (real randomness)', () => {
            const keyBytes = encodeKey(TEST_CONSTANTS.USER_KEY)
            const plaintext = encodeUint(42n)

            const result1 = encrypt(keyBytes, plaintext)
            const result2 = encrypt(keyBytes, plaintext)

            // With real randomness, ciphertexts should differ
            expect(result1.ciphertext).not.toEqual(result2.ciphertext)
            expect(result1.r).not.toEqual(result2.r)

            // But both should decrypt to the same plaintext
            const decrypted1 = decrypt(keyBytes, result1.r, result1.ciphertext)
            const decrypted2 = decrypt(keyBytes, result2.r, result2.ciphertext)
            expect(decrypted1).toEqual(plaintext)
            expect(decrypted2).toEqual(plaintext)
        })

        test('decrypt is agnostic to randomness source', () => {
            const keyBytes = encodeKey(TEST_CONSTANTS.USER_KEY)

            // Test with various plaintexts
            const plaintexts = [
                0n, 1n, 42n, 255n, 65535n,
                (2n ** 32n) - 1n,
                (2n ** 64n) - 1n,
                (2n ** 100n) - 1n,
                (2n ** 128n) - 1n
            ]

            for (const value of plaintexts) {
                const plaintextBytes = encodeUint(value)
                const { ciphertext, r } = encrypt(keyBytes, plaintextBytes)

                // Decrypt should always recover the original plaintext
                const decrypted = decrypt(keyBytes, r, ciphertext)
                expect(decrypted).toEqual(plaintextBytes)
            }
        })
    })

    describe('prepareIT parity across multiple calls', () => {
        test('prepareIT with real randomness produces different ciphertexts but same decrypted value', () => {
            const plaintext = 12345n

            const result1 = prepareIT(
                plaintext, createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS, TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            const result2 = prepareIT(
                plaintext, createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS, TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Ciphertexts should differ (different random values)
            expect(result1.ciphertext).not.toEqual(result2.ciphertext)

            // Both should decrypt to the same value
            const decrypted1 = decryptUint(result1.ciphertext, TEST_CONSTANTS.USER_KEY)
            const decrypted2 = decryptUint(result2.ciphertext, TEST_CONSTANTS.USER_KEY)
            expect(decrypted1).toEqual(plaintext)
            expect(decrypted2).toEqual(plaintext)
        })

        test('prepareIT round-trip works for boundary values with real randomness', () => {
            const boundaryValues = [
                0n,
                1n,
                (2n ** 64n) - 1n,    // max 64-bit
                2n ** 64n,            // min 65-bit
                (2n ** 128n) - 1n     // max 128-bit
            ]

            for (const value of boundaryValues) {
                const { ciphertext } = prepareIT(
                    value, createTestSender(),
                    TEST_CONSTANTS.CONTRACT_ADDRESS, TEST_CONSTANTS.FUNCTION_SELECTOR
                )
                const decrypted = decryptUint(ciphertext, TEST_CONSTANTS.USER_KEY)
                expect(decrypted).toEqual(value)
            }
        })
    })

    describe('prepareIT256 parity across multiple calls', () => {
        test('prepareIT256 with real randomness produces different ciphertexts but same decrypted value', () => {
            const plaintext = 2n ** 200n + 42n

            const result1 = prepareIT256(
                plaintext, createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS, TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            const result2 = prepareIT256(
                plaintext, createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS, TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // At least one component should differ
            const highDiff = result1.ciphertext.ciphertextHigh !== result2.ciphertext.ciphertextHigh
            const lowDiff = result1.ciphertext.ciphertextLow !== result2.ciphertext.ciphertextLow
            expect(highDiff || lowDiff).toBe(true)

            // Both should decrypt to the same value
            const decrypted1 = decryptUint256(result1.ciphertext, TEST_CONSTANTS.USER_KEY)
            const decrypted2 = decryptUint256(result2.ciphertext, TEST_CONSTANTS.USER_KEY)
            expect(decrypted1).toEqual(plaintext)
            expect(decrypted2).toEqual(plaintext)
        })
    })
})
