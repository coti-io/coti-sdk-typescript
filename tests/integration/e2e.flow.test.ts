import { Wallet } from 'ethers'
import {
    prepareIT,
    prepareIT256,
    buildStringInputText,
    decryptUint,
    decryptUint256,
    decryptString
} from '../../src'

// Load test constants from environment variables
const TEST_CONSTANTS = {
    PRIVATE_KEY: process.env.TEST_PRIVATE_KEY || '',
    USER_KEY: process.env.TEST_USER_KEY || '',
    // Use hardcoded test values for contract address and function selector
    // These are just test values and don't need to be in .env
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

describe('Integration: End-to-End Flows', () => {
    describe('prepareIT → decryptUint flow', () => {
        test('complete flow: encrypt and decrypt small value', () => {
            const plaintext = 42n
            const sender = createTestSender()

            // Step 1: Prepare encrypted input text
            const { ciphertext, signature } = prepareIT(
                plaintext,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Step 2: Verify format
            expect(typeof ciphertext).toBe('bigint')
            expect(ciphertext).toBeGreaterThan(0n)
            expect(signature).toBeInstanceOf(Uint8Array)
            expect(signature.length).toBe(65)

            // Step 3: Decrypt and verify
            const decrypted = decryptUint(ciphertext, sender.userKey)
            expect(decrypted).toBe(plaintext)
        })

        test('complete flow: encrypt and decrypt large value', () => {
            const plaintext = (2n ** 128n) - 1n
            const sender = createTestSender()

            const { ciphertext } = prepareIT(
                plaintext,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            const decrypted = decryptUint(ciphertext, sender.userKey)
            expect(decrypted).toBe(plaintext)
        })

        test('complete flow: encrypt and decrypt zero', () => {
            const plaintext = 0n
            const sender = createTestSender()

            const { ciphertext } = prepareIT(
                plaintext,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            const decrypted = decryptUint(ciphertext, sender.userKey)
            expect(decrypted).toBe(plaintext)
        })

        test('different plaintexts produce different ciphertexts', () => {
            const plaintext1 = 100n
            const plaintext2 = 200n
            const sender = createTestSender()

            const { ciphertext: ct1 } = prepareIT(
                plaintext1,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            const { ciphertext: ct2 } = prepareIT(
                plaintext2,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            expect(ct1).not.toBe(ct2)

            // Both should decrypt correctly
            expect(decryptUint(ct1, sender.userKey)).toBe(plaintext1)
            expect(decryptUint(ct2, sender.userKey)).toBe(plaintext2)
        })
    })

    describe('prepareIT256 → decryptUint256 flow', () => {
        test('complete flow: encrypt and decrypt 128-bit value', () => {
            const plaintext = (2n ** 100n) - 1n
            const sender = createTestSender()

            const { ciphertext, signature } = prepareIT256(
                plaintext,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Verify format
            expect(ciphertext).toHaveProperty('ciphertextHigh')
            expect(ciphertext).toHaveProperty('ciphertextLow')
            expect(typeof ciphertext.ciphertextHigh).toBe('bigint')
            expect(typeof ciphertext.ciphertextLow).toBe('bigint')
            expect(signature.length).toBe(65)

            // Decrypt and verify
            const decrypted = decryptUint256(ciphertext, sender.userKey)
            expect(decrypted).toBe(plaintext)
        })

        test('complete flow: encrypt and decrypt 256-bit value', () => {
            const plaintext = (2n ** 256n) - 1n
            const sender = createTestSender()

            const { ciphertext } = prepareIT256(
                plaintext,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            const decrypted = decryptUint256(ciphertext, sender.userKey)
            expect(decrypted).toBe(plaintext)
        })

        test('complete flow: encrypt and decrypt value > 128 bits', () => {
            const plaintext = 2n ** 200n
            const sender = createTestSender()

            const { ciphertext } = prepareIT256(
                plaintext,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            const decrypted = decryptUint256(ciphertext, sender.userKey)
            expect(decrypted).toBe(plaintext)
        })

        test('different plaintexts produce different ciphertexts', () => {
            const plaintext1 = 2n ** 150n
            const plaintext2 = 2n ** 200n
            const sender = createTestSender()

            const { ciphertext: ct1 } = prepareIT256(
                plaintext1,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            const { ciphertext: ct2 } = prepareIT256(
                plaintext2,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            expect(ct1).not.toEqual(ct2)

            // Both should decrypt correctly
            expect(decryptUint256(ct1, sender.userKey)).toBe(plaintext1)
            expect(decryptUint256(ct2, sender.userKey)).toBe(plaintext2)
        })
    })

    describe('buildStringInputText → decryptString flow', () => {
        test('complete flow: encrypt and decrypt short string', () => {
            const plaintext = 'Hello'
            const sender = createTestSender()

            const { ciphertext, signature } = buildStringInputText(
                plaintext,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Verify format
            expect(ciphertext).toHaveProperty('value')
            expect(Array.isArray(ciphertext.value)).toBe(true)
            expect(Array.isArray(signature)).toBe(true)
            expect(ciphertext.value.length).toBe(signature.length)

            // Decrypt and verify
            const decrypted = decryptString(ciphertext, sender.userKey)
            expect(decrypted).toBe(plaintext)
        })

        test('complete flow: encrypt and decrypt long string', () => {
            const plaintext = 'This is a longer string that will be split into multiple chunks for encryption and decryption testing.'
            const sender = createTestSender()

            const { ciphertext } = buildStringInputText(
                plaintext,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            const decrypted = decryptString(ciphertext, sender.userKey)
            expect(decrypted).toBe(plaintext)
        })

        test('complete flow: encrypt and decrypt empty string', () => {
            const plaintext = ''
            const sender = createTestSender()

            const { ciphertext } = buildStringInputText(
                plaintext,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            const decrypted = decryptString(ciphertext, sender.userKey)
            expect(decrypted).toBe(plaintext)
        })

        test('complete flow: encrypt and decrypt string with special characters', () => {
            const plaintext = 'Hello! @#$%^&*()_+-=[]{}|;:,.<>?/~`'
            const sender = createTestSender()

            const { ciphertext } = buildStringInputText(
                plaintext,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            const decrypted = decryptString(ciphertext, sender.userKey)
            expect(decrypted).toBe(plaintext)
        })

        test('different strings produce different ciphertexts', () => {
            const string1 = 'Hello'
            const string2 = 'World'
            const sender = createTestSender()

            const { ciphertext: ct1 } = buildStringInputText(
                string1,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            const { ciphertext: ct2 } = buildStringInputText(
                string2,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            expect(ct1).not.toEqual(ct2)

            // Both should decrypt correctly
            expect(decryptString(ct1, sender.userKey)).toBe(string1)
            expect(decryptString(ct2, sender.userKey)).toBe(string2)
        })
    })

    describe('Multiple operations in sequence', () => {
        test('sequence: prepareIT → prepareIT256 → buildStringInputText', () => {
            const sender = createTestSender()
            const uintValue = 12345n
            const uint256Value = 2n ** 200n
            const stringValue = 'Test string'

            // Operation 1: prepareIT
            const { ciphertext: ct1 } = prepareIT(
                uintValue,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            expect(decryptUint(ct1, sender.userKey)).toBe(uintValue)

            // Operation 2: prepareIT256
            const { ciphertext: ct2 } = prepareIT256(
                uint256Value,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            expect(decryptUint256(ct2, sender.userKey)).toBe(uint256Value)

            // Operation 3: buildStringInputText
            const { ciphertext: ct3 } = buildStringInputText(
                stringValue,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            expect(decryptString(ct3, sender.userKey)).toBe(stringValue)
        })

        test('sequence: multiple prepareIT operations with different values', () => {
            const sender = createTestSender()
            const values = [100n, 200n, 300n, 400n, 500n]

            values.forEach((value) => {
                const { ciphertext } = prepareIT(
                    value,
                    sender,
                    TEST_CONSTANTS.CONTRACT_ADDRESS,
                    TEST_CONSTANTS.FUNCTION_SELECTOR
                )
                expect(decryptUint(ciphertext, sender.userKey)).toBe(value)
            })
        })
    })
})

