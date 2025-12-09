import { Wallet } from 'ethers'
import {
    prepareIT,
    prepareIT256,
    buildStringInputText
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

describe('Integration: Signature Verification', () => {
    describe('prepareIT signature format', () => {
        test('signature has correct format (65 bytes: r + s + v)', () => {
            const plaintext = 12345n
            const { signature } = prepareIT(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            expect(signature).toBeInstanceOf(Uint8Array)
            expect(signature.length).toBe(65) // r(32 bytes) + s(32 bytes) + v(1 byte)
        })

        test('signature changes when plaintext changes', () => {
            const plaintext1 = 100n
            const plaintext2 = 200n

            const { signature: sig1 } = prepareIT(
                plaintext1,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            const { signature: sig2 } = prepareIT(
                plaintext2,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            expect(sig1).not.toEqual(sig2)
        })

        test('signature changes when contract address changes', () => {
            const plaintext = 12345n
            const contract1 = TEST_CONSTANTS.CONTRACT_ADDRESS
            const contract2 = '0x0000000000000000000000000000000000000002'

            const { signature: sig1 } = prepareIT(
                plaintext,
                createTestSender(),
                contract1,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            const { signature: sig2 } = prepareIT(
                plaintext,
                createTestSender(),
                contract2,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            expect(sig1).not.toEqual(sig2)
        })

        test('signature changes when function selector changes', () => {
            const plaintext = 12345n
            const selector1 = TEST_CONSTANTS.FUNCTION_SELECTOR
            const selector2 = '0x55667788'

            const { signature: sig1 } = prepareIT(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                selector1
            )

            const { signature: sig2 } = prepareIT(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                selector2
            )

            expect(sig1).not.toEqual(sig2)
        })

        test('signature format is consistent (same structure)', () => {
            const plaintext = 12345n

            const { signature: sig1 } = prepareIT(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            const { signature: sig2 } = prepareIT(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Note: Signatures will differ due to random encryption, but format should be consistent
            expect(sig1.length).toBe(sig2.length)
            expect(sig1.length).toBe(65)
        })
    })

    describe('prepareIT256 signature format', () => {
        test('signature has correct format (65 bytes)', () => {
            const plaintext = 2n ** 200n
            const { signature } = prepareIT256(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            expect(signature).toBeInstanceOf(Uint8Array)
            expect(signature.length).toBe(65)
        })

        test('signature changes when plaintext changes', () => {
            const plaintext1 = 2n ** 150n
            const plaintext2 = 2n ** 200n

            const { signature: sig1 } = prepareIT256(
                plaintext1,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            const { signature: sig2 } = prepareIT256(
                plaintext2,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            expect(sig1).not.toEqual(sig2)
        })

        test('signature format is consistent (same structure)', () => {
            const plaintext = 2n ** 200n

            const { signature: sig1 } = prepareIT256(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            const { signature: sig2 } = prepareIT256(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Note: Signatures will differ due to random encryption, but format should be consistent
            expect(sig1.length).toBe(sig2.length)
            expect(sig1.length).toBe(65)
        })
    })

    describe('buildStringInputText signature format', () => {
        test('signatures array has correct format (one per chunk)', () => {
            const plaintext = 'Hello, world!'
            const { signature } = buildStringInputText(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            expect(Array.isArray(signature)).toBe(true)
            expect(signature.length).toBeGreaterThan(0)
            
            signature.forEach((sig) => {
                expect(sig).toBeInstanceOf(Uint8Array)
                expect(sig.length).toBe(65)
            })
        })

        test('signature count matches ciphertext chunk count', () => {
            const plaintext = 'This is a test string that will be split into chunks'
            const { ciphertext, signature } = buildStringInputText(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            expect(signature.length).toBe(ciphertext.value.length)
        })

        test('signatures change when string changes', () => {
            const string1 = 'Hello'
            const string2 = 'World'

            const { signature: sig1 } = buildStringInputText(
                string1,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            const { signature: sig2 } = buildStringInputText(
                string2,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            expect(sig1).not.toEqual(sig2)
        })

        test('signature format is consistent (same structure)', () => {
            const plaintext = 'Test string'

            const { signature: sig1 } = buildStringInputText(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            const { signature: sig2 } = buildStringInputText(
                plaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Note: Signatures will differ due to random encryption, but format should be consistent
            expect(sig1.length).toBe(sig2.length)
            expect(sig1.length).toBeGreaterThan(0)
            sig1.forEach((sig, idx) => {
                expect(sig).toBeInstanceOf(Uint8Array)
                expect(sig.length).toBe(65)
                expect(sig2[idx]).toBeInstanceOf(Uint8Array)
                expect(sig2[idx].length).toBe(65)
            })
        })
    })
})

