import { Wallet } from 'ethers'
import {
    buildInputText,
    decryptUint
} from '../../src'

// Load test constants from environment variables
const TEST_CONSTANTS = {
    PRIVATE_KEY: process.env.TEST_PRIVATE_KEY || '',
    USER_KEY: process.env.TEST_USER_KEY || '',
    CONTRACT_ADDRESS: '0x0000000000000000000000000000000000000001',
    FUNCTION_SELECTOR: '0x11223344'
}

// Validate that all required environment variables are set
if (!TEST_CONSTANTS.PRIVATE_KEY || !TEST_CONSTANTS.USER_KEY) {
    throw new Error(
        'Missing required test environment variables. ' +
        'Please create a .env file with TEST_PRIVATE_KEY and TEST_USER_KEY. ' +
        'See example.env for reference.'
    )
}

function createTestSender() {
    return {
        wallet: new Wallet(TEST_CONSTANTS.PRIVATE_KEY),
        userKey: TEST_CONSTANTS.USER_KEY
    }
}

/**
 * Tests for buildInputText's 64-bit plaintext validation.
 * 
 * buildInputText restricts plaintexts to < 2^64, unlike prepareIT which allows up to 128-bit.
 * This is the only uncovered code path (line 194 in crypto_utils.ts).
 */
describe('Unit: buildInputText 64-bit Validation', () => {
    test('throws RangeError when plaintext is exactly 2^64', () => {
        const plaintext = 2n ** 64n // Exactly 64-bit boundary
        expect(() => buildInputText(
            plaintext,
            createTestSender(),
            TEST_CONSTANTS.CONTRACT_ADDRESS,
            TEST_CONSTANTS.FUNCTION_SELECTOR
        )).toThrow(RangeError)
        expect(() => buildInputText(
            plaintext,
            createTestSender(),
            TEST_CONSTANTS.CONTRACT_ADDRESS,
            TEST_CONSTANTS.FUNCTION_SELECTOR
        )).toThrow('Plaintext size must be 64 bits or smaller.')
    })

    test('throws RangeError when plaintext exceeds 2^64', () => {
        const plaintext = 2n ** 64n + 1n // Just above 64-bit limit
        expect(() => buildInputText(
            plaintext,
            createTestSender(),
            TEST_CONSTANTS.CONTRACT_ADDRESS,
            TEST_CONSTANTS.FUNCTION_SELECTOR
        )).toThrow(RangeError)
    })

    test('throws RangeError when plaintext is 128-bit (far above 64-bit limit)', () => {
        const plaintext = (2n ** 128n) - 1n // 128-bit value
        expect(() => buildInputText(
            plaintext,
            createTestSender(),
            TEST_CONSTANTS.CONTRACT_ADDRESS,
            TEST_CONSTANTS.FUNCTION_SELECTOR
        )).toThrow(RangeError)
    })

    test('succeeds with plaintext = 2^64 - 1 (maximum valid 64-bit value)', () => {
        const plaintext = (2n ** 64n) - 1n // Largest valid value for buildInputText
        const result = buildInputText(
            plaintext,
            createTestSender(),
            TEST_CONSTANTS.CONTRACT_ADDRESS,
            TEST_CONSTANTS.FUNCTION_SELECTOR
        )

        expect(result).toHaveProperty('ciphertext')
        expect(result).toHaveProperty('signature')
        expect(typeof result.ciphertext).toBe('bigint')
        expect(result.ciphertext).toBeGreaterThan(0n)

        // Round-trip verification
        const decrypted = decryptUint(result.ciphertext, TEST_CONSTANTS.USER_KEY)
        expect(decrypted).toEqual(plaintext)
    })

    test('succeeds with zero plaintext', () => {
        const plaintext = 0n
        const result = buildInputText(
            plaintext,
            createTestSender(),
            TEST_CONSTANTS.CONTRACT_ADDRESS,
            TEST_CONSTANTS.FUNCTION_SELECTOR
        )

        expect(result).toHaveProperty('ciphertext')
        const decrypted = decryptUint(result.ciphertext, TEST_CONSTANTS.USER_KEY)
        expect(decrypted).toEqual(plaintext)
    })

    test('succeeds with small values within 64-bit range', () => {
        const values = [1n, 255n, 65535n, 4294967295n, 999999999999n]
        for (const plaintext of values) {
            const result = buildInputText(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            const decrypted = decryptUint(result.ciphertext, TEST_CONSTANTS.USER_KEY)
            expect(decrypted).toEqual(plaintext)
        }
    })
})
