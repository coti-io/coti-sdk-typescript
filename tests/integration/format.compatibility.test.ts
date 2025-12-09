import { Wallet } from 'ethers'
import {
    prepareIT,
    prepareIT256,
    buildStringInputText
} from '../../src'
import { itUint, itUint256, itString } from '../../src/types'

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

describe('Integration: Format Compatibility', () => {
    describe('itUint format (prepareIT output)', () => {
        test('output matches itUint type structure', () => {
            const plaintext = 12345n
            const result = prepareIT(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Verify structure matches itUint type
            expect(result).toHaveProperty('ciphertext')
            expect(result).toHaveProperty('signature')
            expect(typeof result.ciphertext).toBe('bigint')
            expect(result.signature).toBeInstanceOf(Uint8Array)
        })

        test('ciphertext is valid BigInt for contract submission', () => {
            const plaintext = 12345n
            const { ciphertext } = prepareIT(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Verify it's a valid BigInt that can be used in contracts
            expect(typeof ciphertext).toBe('bigint')
            expect(ciphertext).toBeGreaterThan(0n)
            expect(ciphertext.toString()).toMatch(/^\d+$/) // Valid number string
        })

        test('signature can be converted to bytes format for contracts', () => {
            const plaintext = 12345n
            const { signature } = prepareIT(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Verify signature format is compatible with contract bytes parameter
            expect(signature).toBeInstanceOf(Uint8Array)
            expect(signature.length).toBe(65)
            
            // Can be converted to hex string for contract calls
            const sigArray = signature instanceof Uint8Array ? signature : new Uint8Array()
            const hexString = '0x' + Array.from(sigArray)
                .map(b => b.toString(16).padStart(2, '0'))
                .join('')
            expect(hexString.length).toBe(132) // 0x + 65 bytes * 2 hex chars
        })
    })

    describe('itUint256 format (prepareIT256 output)', () => {
        test('output matches itUint256 type structure', () => {
            const plaintext = 2n ** 200n
            const result = prepareIT256(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Verify structure matches itUint256 type
            expect(result).toHaveProperty('ciphertext')
            expect(result).toHaveProperty('signature')
            expect(result.ciphertext).toHaveProperty('ciphertextHigh')
            expect(result.ciphertext).toHaveProperty('ciphertextLow')
            expect(typeof result.ciphertext.ciphertextHigh).toBe('bigint')
            expect(typeof result.ciphertext.ciphertextLow).toBe('bigint')
            expect(result.signature).toBeInstanceOf(Uint8Array)
        })

        test('ciphertextHigh and ciphertextLow are valid BigInts', () => {
            const plaintext = 2n ** 200n
            const { ciphertext } = prepareIT256(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Verify both parts are valid BigInts
            expect(typeof ciphertext.ciphertextHigh).toBe('bigint')
            expect(typeof ciphertext.ciphertextLow).toBe('bigint')
            expect(ciphertext.ciphertextHigh).toBeGreaterThan(0n)
            expect(ciphertext.ciphertextLow).toBeGreaterThan(0n)
        })

        test('format is compatible with contract struct parameters', () => {
            const plaintext = 2n ** 200n
            const { ciphertext } = prepareIT256(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Can be serialized as contract struct: { uint256 ciphertextHigh, uint256 ciphertextLow }
            const structFormat = {
                ciphertextHigh: ciphertext.ciphertextHigh.toString(),
                ciphertextLow: ciphertext.ciphertextLow.toString()
            }

            expect(structFormat.ciphertextHigh).toBeTruthy()
            expect(structFormat.ciphertextLow).toBeTruthy()
        })
    })

    describe('itString format (buildStringInputText output)', () => {
        test('output matches itString type structure', () => {
            const plaintext = 'Hello, world!'
            const result = buildStringInputText(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Verify structure matches itString type
            expect(result).toHaveProperty('ciphertext')
            expect(result).toHaveProperty('signature')
            expect(result.ciphertext).toHaveProperty('value')
            expect(Array.isArray(result.ciphertext.value)).toBe(true)
            expect(Array.isArray(result.signature)).toBe(true)
        })

        test('ciphertext.value is array of BigInts for contract submission', () => {
            const plaintext = 'Test string'
            const { ciphertext } = buildStringInputText(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Verify array format
            expect(Array.isArray(ciphertext.value)).toBe(true)
            expect(ciphertext.value.length).toBeGreaterThan(0)

            // Verify each element is BigInt
            ciphertext.value.forEach((ct) => {
                expect(typeof ct).toBe('bigint')
                expect(ct).toBeGreaterThan(0n)
            })
        })

        test('signature array matches ciphertext array length', () => {
            const plaintext = 'This is a test string'
            const { ciphertext, signature } = buildStringInputText(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            expect(signature.length).toBe(ciphertext.value.length)
        })

        test('format is compatible with contract array parameters', () => {
            const plaintext = 'Hello'
            const { ciphertext, signature } = buildStringInputText(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Can be serialized for contract: (uint256[] ciphertext, bytes[] signature)
            const ciphertextArray = ciphertext.value.map(ct => ct.toString())
            const signatureArray = signature.map(sig => {
                const sigArray = sig instanceof Uint8Array ? sig : new Uint8Array()
                return '0x' + Array.from(sigArray)
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('')
            })

            expect(Array.isArray(ciphertextArray)).toBe(true)
            expect(Array.isArray(signatureArray)).toBe(true)
            expect(ciphertextArray.length).toBe(signatureArray.length)
        })
    })

    describe('Contract address and function selector format', () => {
        test('contract address format is valid', () => {
            const plaintext = 12345n
            const validAddress = TEST_CONSTANTS.CONTRACT_ADDRESS

            // Should not throw with valid address format
            expect(() => {
                prepareIT(
                    plaintext,
                    createTestSender(),
                    validAddress,
                    TEST_CONSTANTS.FUNCTION_SELECTOR
                )
            }).not.toThrow()
        })

        test('function selector format is valid (4 bytes)', () => {
            const plaintext = 12345n
            const validSelector = TEST_CONSTANTS.FUNCTION_SELECTOR

            // Should not throw with valid selector format
            expect(() => {
                prepareIT(
                    plaintext,
                    createTestSender(),
                    TEST_CONSTANTS.CONTRACT_ADDRESS,
                    validSelector
                )
            }).not.toThrow()

            // Verify selector is 4 bytes (0x + 8 hex chars)
            expect(validSelector.startsWith('0x')).toBe(true)
            expect(validSelector.length).toBe(10) // 0x + 8 hex characters
        })
    })

    describe('Data type conversions for contract compatibility', () => {
        test('ciphertext can be converted to hex string', () => {
            const plaintext = 12345n
            const { ciphertext } = prepareIT(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Convert to hex string (contract format)
            const hexString = '0x' + ciphertext.toString(16)
            expect(hexString.startsWith('0x')).toBe(true)
            expect(hexString.length).toBeGreaterThan(2)
        })

        test('signature can be converted to hex string', () => {
            const plaintext = 12345n
            const { signature } = prepareIT(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Convert to hex string (contract format)
            const sigArray = signature instanceof Uint8Array ? signature : new Uint8Array()
            const hexString = '0x' + Array.from(sigArray)
                .map(b => b.toString(16).padStart(2, '0'))
                .join('')
            expect(hexString.startsWith('0x')).toBe(true)
            expect(hexString.length).toBe(132) // 0x + 65 bytes * 2
        })

        test('ciphertextHigh and ciphertextLow can be converted to hex strings', () => {
            const plaintext = 2n ** 200n
            const { ciphertext } = prepareIT256(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            const highHex = '0x' + ciphertext.ciphertextHigh.toString(16)
            const lowHex = '0x' + ciphertext.ciphertextLow.toString(16)

            expect(highHex.startsWith('0x')).toBe(true)
            expect(lowHex.startsWith('0x')).toBe(true)
        })
    })
})

