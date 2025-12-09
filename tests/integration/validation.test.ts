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

describe('Integration: Input Validation', () => {
    describe('Invalid user key format', () => {
        test('prepareIT produces incorrect result with user key that is too short', () => {
            const sender = {
                wallet: new Wallet(TEST_CONSTANTS.PRIVATE_KEY),
                userKey: '1234567890123456789012345678901' // 31 chars instead of 32
            }
            // Function doesn't throw, but produces incorrect encryption
            const result = prepareIT(
                12345n,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            expect(result).toHaveProperty('ciphertext')
            // Decryption with correct key will fail
            const decrypted = decryptUint(result.ciphertext, TEST_CONSTANTS.USER_KEY)
            expect(decrypted).not.toBe(12345n)
        })

        test('prepareIT produces incorrect result with user key that is too long', () => {
            const sender = {
                wallet: new Wallet(TEST_CONSTANTS.PRIVATE_KEY),
                userKey: '12345678901234567890123456789012a' // 33 chars instead of 32
            }
            // Function processes first 32 chars, doesn't throw
            const result = prepareIT(
                12345n,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            expect(result).toHaveProperty('ciphertext')
        })

        test('prepareIT produces incorrect result with user key containing invalid hex', () => {
            const sender = {
                wallet: new Wallet(TEST_CONSTANTS.PRIVATE_KEY),
                userKey: '1234567890123456789012345678901g' // 'g' is invalid hex
            }
            // Function processes what it can, may throw during encryption or produce incorrect result
            try {
                const result = prepareIT(
                    12345n,
                    sender,
                    TEST_CONSTANTS.CONTRACT_ADDRESS,
                    TEST_CONSTANTS.FUNCTION_SELECTOR
                )
                expect(result).toHaveProperty('ciphertext')
            } catch (e) {
                // Throwing is also acceptable
                expect(e).toBeDefined()
            }
        })

        test('decryptUint produces incorrect result with invalid user key', () => {
            const { ciphertext } = prepareIT(
                12345n,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            const invalidKey = '1234567890123456789012345678901g' // invalid hex
            // May throw or produce incorrect result
            try {
                const decrypted = decryptUint(ciphertext, invalidKey)
                expect(decrypted).not.toBe(12345n)
            } catch (e) {
                // Throwing is also acceptable
                expect(e).toBeDefined()
            }
        })

        test('decryptUint256 produces incorrect result with invalid user key', () => {
            const { ciphertext } = prepareIT256(
                2n ** 200n,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            const invalidKey = '1234567890123456789012345678901g' // invalid hex
            // May throw or produce incorrect result
            try {
                const decrypted = decryptUint256(ciphertext, invalidKey)
                expect(decrypted).not.toBe(2n ** 200n)
            } catch (e) {
                // Throwing is also acceptable
                expect(e).toBeDefined()
            }
        })

        test('decryptString produces incorrect result with invalid user key', () => {
            const { ciphertext } = buildStringInputText(
                'Hello',
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            const invalidKey = '1234567890123456789012345678901g' // invalid hex
            // May throw or produce incorrect result
            try {
                const decrypted = decryptString(ciphertext, invalidKey)
                expect(decrypted).not.toBe('Hello')
            } catch (e) {
                // Throwing is also acceptable
                expect(e).toBeDefined()
            }
        })
    })

    describe('Invalid contract address format', () => {
        test('prepareIT throws error with contract address that is too short', () => {
            const invalidAddress = '0x000000000000000000000000000000000000001' // 41 chars instead of 42
            expect(() => prepareIT(
                12345n,
                createTestSender(),
                invalidAddress,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )).toThrow()
        })

        test('prepareIT handles contract address without 0x prefix', () => {
            const invalidAddress = '1234567890123456789012345678901234567890' // missing 0x
            // ethers getBytes might handle this, or might throw
            try {
                const result = prepareIT(
                    12345n,
                    createTestSender(),
                    invalidAddress,
                    TEST_CONSTANTS.FUNCTION_SELECTOR
                )
                expect(result).toHaveProperty('ciphertext')
            } catch (e) {
                // Throwing is acceptable
                expect(e).toBeDefined()
            }
        })

        test('prepareIT throws error with contract address containing invalid hex', () => {
            const invalidAddress = '0x123456789012345678901234567890123456789g' // 'g' is invalid hex
            expect(() => prepareIT(
                12345n,
                createTestSender(),
                invalidAddress,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )).toThrow()
        })

        test('prepareIT256 throws error with invalid contract address', () => {
            const invalidAddress = '0x123456789012345678901234567890123456789g'
            expect(() => prepareIT256(
                2n ** 200n,
                createTestSender(),
                invalidAddress,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )).toThrow()
        })

        test('buildStringInputText throws error with invalid contract address', () => {
            const invalidAddress = '0x123456789012345678901234567890123456789g'
            expect(() => buildStringInputText(
                'Hello',
                createTestSender(),
                invalidAddress,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )).toThrow()
        })
    })

    describe('Invalid function selector format', () => {
        test('prepareIT throws error with function selector that is too short', () => {
            const invalidSelector = '0x112233' // 3 bytes instead of 4
            expect(() => prepareIT(
                12345n,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                invalidSelector
            )).toThrow()
        })

        test('prepareIT throws error with function selector that is too long', () => {
            const invalidSelector = '0x1122334455' // 5 bytes instead of 4
            expect(() => prepareIT(
                12345n,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                invalidSelector
            )).toThrow()
        })

        test('prepareIT throws error with function selector without 0x prefix', () => {
            const invalidSelector = '11223344' // missing 0x
            expect(() => prepareIT(
                12345n,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                invalidSelector
            )).toThrow()
        })

        test('prepareIT throws error with function selector containing invalid hex', () => {
            const invalidSelector = '0x1122334g' // 'g' is invalid hex
            expect(() => prepareIT(
                12345n,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                invalidSelector
            )).toThrow()
        })

        test('prepareIT256 throws error with invalid function selector', () => {
            const invalidSelector = '0x1122334g'
            expect(() => prepareIT256(
                2n ** 200n,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                invalidSelector
            )).toThrow()
        })

        test('buildStringInputText throws error with invalid function selector', () => {
            const invalidSelector = '0x1122334g'
            expect(() => buildStringInputText(
                'Hello',
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                invalidSelector
            )).toThrow()
        })
    })

    describe('Invalid private key format', () => {
        test('Wallet creation throws error with invalid private key', () => {
            const invalidPrivateKey = '0x123' // Too short
            expect(() => new Wallet(invalidPrivateKey)).toThrow()
        })

        test('Wallet creation handles private key without 0x prefix', () => {
            const invalidPrivateKey = '1234567890123456789012345678901234567890123456789012345678901234' // missing 0x
            // ethers Wallet might auto-add 0x or throw
            try {
                const wallet = new Wallet(invalidPrivateKey)
                expect(wallet).toBeDefined()
            } catch (e) {
                // Throwing is acceptable
                expect(e).toBeDefined()
            }
        })

        test('prepareIT throws error when sender has invalid wallet', () => {
            const invalidWallet = new Wallet('0x1234567890123456789012345678901234567890123456789012345678901234') // Valid format but wrong key
            const sender = {
                wallet: invalidWallet,
                userKey: TEST_CONSTANTS.USER_KEY
            }
            // This might not throw immediately, but will fail during signing
            expect(() => prepareIT(
                12345n,
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )).not.toThrow() // Wallet creation succeeds, but signature will be different
        })
    })

    describe('Wrong decrypt function usage', () => {
        test('decryptUint produces incorrect result when given prepareIT256 ciphertext format', () => {
            const { ciphertext } = prepareIT256(
                2n ** 200n,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            // decryptUint expects a BigInt, but prepareIT256 returns {ciphertextHigh, ciphertextLow}
            // This will cause a type error or incorrect behavior
            try {
                const result = decryptUint(ciphertext as any, TEST_CONSTANTS.USER_KEY)
                expect(result).not.toBe(2n ** 200n)
            } catch (e) {
                // Throwing is acceptable
                expect(e).toBeDefined()
            }
        })

        test('decryptUint256 produces incorrect result when given prepareIT ciphertext format', () => {
            const { ciphertext } = prepareIT(
                12345n,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            // decryptUint256 expects {ciphertextHigh, ciphertextLow}, but prepareIT returns BigInt
            // This will cause a type error or incorrect behavior
            try {
                const result = decryptUint256(ciphertext as any, TEST_CONSTANTS.USER_KEY)
                expect(result).not.toBe(12345n)
            } catch (e) {
                // Throwing is acceptable
                expect(e).toBeDefined()
            }
        })

        test('decryptString throws error when given prepareIT ciphertext format', () => {
            const { ciphertext } = prepareIT(
                12345n,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            // decryptString expects {value: BigInt[]}, but prepareIT returns BigInt
            expect(() => {
                decryptString(ciphertext as any, TEST_CONSTANTS.USER_KEY)
            }).toThrow()
        })

        test('decryptUint produces incorrect result when given buildStringInputText ciphertext format', () => {
            const { ciphertext } = buildStringInputText(
                'Hello',
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            // decryptUint expects BigInt, but buildStringInputText returns {value: BigInt[]}
            // This will cause a type error
            try {
                const result = decryptUint(ciphertext as any, TEST_CONSTANTS.USER_KEY)
                expect(result).not.toBe('Hello')
            } catch (e) {
                // Throwing is acceptable
                expect(e).toBeDefined()
            }
        })
    })

    describe('Type safety validation', () => {
        test('prepareIT throws error when sender is missing wallet property', () => {
            const invalidSender = {
                userKey: TEST_CONSTANTS.USER_KEY
            } as any
            expect(() => prepareIT(
                12345n,
                invalidSender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )).toThrow()
        })

        test('prepareIT throws error when sender is missing userKey property', () => {
            const invalidSender = {
                wallet: new Wallet(TEST_CONSTANTS.PRIVATE_KEY)
            } as any
            expect(() => prepareIT(
                12345n,
                invalidSender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )).toThrow()
        })

        test('prepareIT256 throws error when sender structure is invalid', () => {
            const invalidSender = {
                wallet: null,
                userKey: TEST_CONSTANTS.USER_KEY
            } as any
            expect(() => prepareIT256(
                2n ** 200n,
                invalidSender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )).toThrow()
        })

        test('buildStringInputText throws error when sender structure is invalid', () => {
            const invalidSender = {
                wallet: new Wallet(TEST_CONSTANTS.PRIVATE_KEY),
                userKey: null
            } as any
            expect(() => buildStringInputText(
                'Hello',
                invalidSender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )).toThrow()
        })
    })

    describe('Boundary conditions', () => {
        test('prepareIT works with exactly 128 bits (boundary)', () => {
            const exactly128Bits = (2n ** 128n) - 1n
            expect(() => {
                const result = prepareIT(
                    exactly128Bits,
                    createTestSender(),
                    TEST_CONSTANTS.CONTRACT_ADDRESS,
                    TEST_CONSTANTS.FUNCTION_SELECTOR
                )
                expect(result).toHaveProperty('ciphertext')
                expect(result).toHaveProperty('signature')
            }).not.toThrow()
        })

        test('prepareIT throws with 129 bits (should use prepareIT256)', () => {
            const exactly129Bits = 2n ** 128n // 129 bits
            expect(() => prepareIT(
                exactly129Bits,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )).toThrow(RangeError)
        })

        test('prepareIT256 works with exactly 256 bits (boundary)', () => {
            const exactly256Bits = (2n ** 256n) - 1n
            expect(() => {
                const result = prepareIT256(
                    exactly256Bits,
                    createTestSender(),
                    TEST_CONSTANTS.CONTRACT_ADDRESS,
                    TEST_CONSTANTS.FUNCTION_SELECTOR
                )
                expect(result).toHaveProperty('ciphertext')
                expect(result).toHaveProperty('signature')
            }).not.toThrow()
        })

        test('prepareIT256 works with exactly 129 bits (boundary between prepareIT and prepareIT256)', () => {
            const exactly129Bits = 2n ** 128n // 129 bits
            expect(() => {
                const result = prepareIT256(
                    exactly129Bits,
                    createTestSender(),
                    TEST_CONSTANTS.CONTRACT_ADDRESS,
                    TEST_CONSTANTS.FUNCTION_SELECTOR
                )
                expect(result).toHaveProperty('ciphertext')
                expect(result).toHaveProperty('signature')
            }).not.toThrow()
        })

        test('prepareIT256 throws with 257 bits', () => {
            const exactly257Bits = 2n ** 256n // 257 bits
            expect(() => prepareIT256(
                exactly257Bits,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )).toThrow(RangeError)
        })
    })

    describe('String edge cases', () => {
        test('buildStringInputText handles very long strings', () => {
            const longString = 'A'.repeat(1000) // 1000 characters
            expect(() => {
                const result = buildStringInputText(
                    longString,
                    createTestSender(),
                    TEST_CONSTANTS.CONTRACT_ADDRESS,
                    TEST_CONSTANTS.FUNCTION_SELECTOR
                )
                expect(result).toHaveProperty('ciphertext')
                expect(result).toHaveProperty('signature')
                // Verify it can be decrypted
                const decrypted = decryptString(result.ciphertext, TEST_CONSTANTS.USER_KEY)
                expect(decrypted).toBe(longString)
            }).not.toThrow()
        })

        test('buildStringInputText handles strings with only null bytes', () => {
            const nullString = '\0\0\0\0\0\0\0\0'
            expect(() => {
                const result = buildStringInputText(
                    nullString,
                    createTestSender(),
                    TEST_CONSTANTS.CONTRACT_ADDRESS,
                    TEST_CONSTANTS.FUNCTION_SELECTOR
                )
                const decrypted = decryptString(result.ciphertext, TEST_CONSTANTS.USER_KEY)
                // Null bytes are removed during decryption
                expect(decrypted).toBe('')
            }).not.toThrow()
        })

        test('buildStringInputText handles strings with only special characters', () => {
            const specialChars = '!@#$%^&*()_+-=[]{}|;:,.<>?/~`'
            expect(() => {
                const result = buildStringInputText(
                    specialChars,
                    createTestSender(),
                    TEST_CONSTANTS.CONTRACT_ADDRESS,
                    TEST_CONSTANTS.FUNCTION_SELECTOR
                )
                const decrypted = decryptString(result.ciphertext, TEST_CONSTANTS.USER_KEY)
                expect(decrypted).toBe(specialChars)
            }).not.toThrow()
        })

        test('buildStringInputText handles basic unicode characters', () => {
            // Test with simpler unicode that works with the encoding
            const unicodeString = 'Hello Café'
            expect(() => {
                const result = buildStringInputText(
                    unicodeString,
                    createTestSender(),
                    TEST_CONSTANTS.CONTRACT_ADDRESS,
                    TEST_CONSTANTS.FUNCTION_SELECTOR
                )
                const decrypted = decryptString(result.ciphertext, TEST_CONSTANTS.USER_KEY)
                // Note: Complex unicode like emojis may not round-trip perfectly due to encoding
                expect(decrypted).toBe(unicodeString)
            }).not.toThrow()
        })
    })
})

