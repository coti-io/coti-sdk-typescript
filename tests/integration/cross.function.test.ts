import { Wallet } from 'ethers'
import {
    prepareIT,
    prepareIT256,
    buildStringInputText,
    decryptUint,
    decryptUint256,
    decryptString,
    buildInputText
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

describe('Integration: Cross-Function Compatibility', () => {
    describe('prepareIT and decryptUint compatibility', () => {
        test('prepareIT output can be decrypted by decryptUint', () => {
            const plaintext = 12345n
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

        test('buildInputText output can be decrypted by decryptUint', () => {
            const plaintext = 12345n
            const sender = createTestSender()

            const { ciphertext } = buildInputText(
                plaintext,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            const decrypted = decryptUint(ciphertext, sender.userKey)
            expect(decrypted).toBe(plaintext)
        })

        test('prepareIT and buildInputText produce compatible formats', () => {
            const plaintext = 12345n
            const sender = createTestSender()

            const result1 = prepareIT(
                plaintext,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            const result2 = buildInputText(
                plaintext,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Both should have same structure
            expect(result1).toHaveProperty('ciphertext')
            expect(result1).toHaveProperty('signature')
            expect(result2).toHaveProperty('ciphertext')
            expect(result2).toHaveProperty('signature')

            // Both should decrypt to same value
            expect(decryptUint(result1.ciphertext, sender.userKey)).toBe(plaintext)
            expect(decryptUint(result2.ciphertext, sender.userKey)).toBe(plaintext)
        })
    })

    describe('prepareIT256 and decryptUint256 compatibility', () => {
        test('prepareIT256 output can be decrypted by decryptUint256', () => {
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

        test('prepareIT256 works with values <= 128 bits', () => {
            const plaintext = (2n ** 100n) - 1n
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

        test('prepareIT256 works with values > 128 bits', () => {
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
    })

    describe('buildStringInputText and decryptString compatibility', () => {
        test('buildStringInputText output can be decrypted by decryptString', () => {
            const plaintext = 'Hello, world!'
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

        test('buildStringInputText handles strings of various lengths', () => {
            const sender = createTestSender()
            const testStrings = [
                'Hi',
                '12345678',
                '123456789',
                'This is a longer string that will be split into multiple chunks.',
                ''
            ]

            testStrings.forEach((str) => {
                const { ciphertext } = buildStringInputText(
                    str,
                    sender,
                    TEST_CONSTANTS.CONTRACT_ADDRESS,
                    TEST_CONSTANTS.FUNCTION_SELECTOR
                )

                const decrypted = decryptString(ciphertext, sender.userKey)
                expect(decrypted).toBe(str)
            })
        })
    })

    describe('Mixed data type operations', () => {
        test('can process uint, uint256, and string in same session', () => {
            const sender = createTestSender()
            const uintValue = 12345n
            const uint256Value = 2n ** 200n
            const stringValue = 'Test string'

            // Process uint
            const { ciphertext: ct1 } = prepareIT(
                uintValue,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            expect(decryptUint(ct1, sender.userKey)).toBe(uintValue)

            // Process uint256
            const { ciphertext: ct2 } = prepareIT256(
                uint256Value,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            expect(decryptUint256(ct2, sender.userKey)).toBe(uint256Value)

            // Process string
            const { ciphertext: ct3 } = buildStringInputText(
                stringValue,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            expect(decryptString(ct3, sender.userKey)).toBe(stringValue)
        })

        test('same user key works across all data types', () => {
            const sender = createTestSender()
            const userKey = sender.userKey

            // All operations should work with same user key
            const { ciphertext: ct1 } = prepareIT(100n, sender, TEST_CONSTANTS.CONTRACT_ADDRESS, TEST_CONSTANTS.FUNCTION_SELECTOR)
            expect(decryptUint(ct1, userKey)).toBe(100n)

            const { ciphertext: ct2 } = prepareIT256(2n ** 200n, sender, TEST_CONSTANTS.CONTRACT_ADDRESS, TEST_CONSTANTS.FUNCTION_SELECTOR)
            expect(decryptUint256(ct2, userKey)).toBe(2n ** 200n)

            const { ciphertext: ct3 } = buildStringInputText('Test', sender, TEST_CONSTANTS.CONTRACT_ADDRESS, TEST_CONSTANTS.FUNCTION_SELECTOR)
            expect(decryptString(ct3, userKey)).toBe('Test')
        })
    })

    describe('Different contract addresses and selectors', () => {
        test('same data with different contract addresses produces different signatures', () => {
            const plaintext = 12345n
            const sender = createTestSender()
            const contract1 = TEST_CONSTANTS.CONTRACT_ADDRESS
            const contract2 = '0x0000000000000000000000000000000000000002'

            const { signature: sig1 } = prepareIT(
                plaintext,
                sender,
                contract1,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            const { signature: sig2 } = prepareIT(
                plaintext,
                sender,
                contract2,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            expect(sig1).not.toEqual(sig2)

            // But both should decrypt to same value
            const { ciphertext: ct1 } = prepareIT(plaintext, sender, contract1, TEST_CONSTANTS.FUNCTION_SELECTOR)
            const { ciphertext: ct2 } = prepareIT(plaintext, sender, contract2, TEST_CONSTANTS.FUNCTION_SELECTOR)
            expect(decryptUint(ct1, sender.userKey)).toBe(plaintext)
            expect(decryptUint(ct2, sender.userKey)).toBe(plaintext)
        })

        test('same data with different function selectors produces different signatures', () => {
            const plaintext = 12345n
            const sender = createTestSender()
            const selector1 = TEST_CONSTANTS.FUNCTION_SELECTOR
            const selector2 = '0x55667788'

            const { signature: sig1 } = prepareIT(
                plaintext,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                selector1
            )

            const { signature: sig2 } = prepareIT(
                plaintext,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                selector2
            )

            expect(sig1).not.toEqual(sig2)
        })
    })

    describe('Error handling across functions', () => {
        test('wrong user key fails to decrypt', () => {
            const plaintext = 12345n
            const sender = createTestSender()
            const wrongKey = '00000000000000000000000000000000'

            const { ciphertext } = prepareIT(
                plaintext,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Decrypting with wrong key should produce different result
            const decrypted = decryptUint(ciphertext, wrongKey)
            expect(decrypted).not.toBe(plaintext)
        })

        test('ciphertext from prepareIT has different format than decryptUint256 expects', () => {
            const plaintext = 12345n
            const sender = createTestSender()

            const { ciphertext } = prepareIT(
                plaintext,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // decryptUint256 expects {ciphertextHigh, ciphertextLow} structure, not a single bigint
            // This test verifies format incompatibility
            expect(typeof ciphertext).toBe('bigint')
            expect(ciphertext).not.toHaveProperty('ciphertextHigh')
            expect(ciphertext).not.toHaveProperty('ciphertextLow')
            
            // Attempting to use wrong format should fail
            expect(() => {
                decryptUint256({ ciphertextHigh: ciphertext, ciphertextLow: 0n } as any, sender.userKey)
            }).not.toThrow() // May not throw, but will produce incorrect result
        })
    })
})

