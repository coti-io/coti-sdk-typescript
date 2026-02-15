import { Wallet } from 'ethers'
import {
    prepareIT,
    decryptUint,
} from '../../src'

// Load test constants from environment variables or use defaults
const TEST_PRIVATE_KEY = process.env.TEST_PRIVATE_KEY || '0xabc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abcd'
const TEST_USER_KEY = process.env.TEST_USER_KEY || '00112233445566778899aabbccddeeff'

const TEST_CONSTANTS = {
    PRIVATE_KEY: TEST_PRIVATE_KEY,
    USER_KEY: TEST_USER_KEY,
    CONTRACT_ADDRESS: '0x0000000000000000000000000000000000000001',
    FUNCTION_SELECTOR: '0x11223344'
}

function createTestSender() {
    return {
        wallet: new Wallet(TEST_CONSTANTS.PRIVATE_KEY),
        userKey: TEST_CONSTANTS.USER_KEY
    }
}

describe('Integration: Boolean Flow (itBool)', () => {
    test('round-trip: prepareIT and decryptUint with boolean TRUE (1n)', () => {
        const plaintext = 1n
        const sender = createTestSender()

        const { ciphertext, signature } = prepareIT(
            plaintext,
            sender,
            TEST_CONSTANTS.CONTRACT_ADDRESS,
            TEST_CONSTANTS.FUNCTION_SELECTOR
        )

        expect(ciphertext).toBeGreaterThan(0n)
        expect(signature).toBeInstanceOf(Uint8Array)

        const decrypted = decryptUint(ciphertext, sender.userKey)
        expect(decrypted).toBe(1n)
    })

    test('round-trip: prepareIT and decryptUint with boolean FALSE (0n)', () => {
        const plaintext = 0n
        const sender = createTestSender()

        const { ciphertext, signature } = prepareIT(
            plaintext,
            sender,
            TEST_CONSTANTS.CONTRACT_ADDRESS,
            TEST_CONSTANTS.FUNCTION_SELECTOR
        )

        expect(ciphertext).toBeGreaterThan(0n)
        expect(signature).toBeInstanceOf(Uint8Array)

        const decrypted = decryptUint(ciphertext, sender.userKey)
        expect(decrypted).toBe(0n)
    })

    test('utility: converting JS boolean to SDK-compatible bigint', () => {
        const jsBoolTrue = true
        const jsBoolFalse = false

        const sdkBoolTrue = jsBoolTrue ? 1n : 0n
        const sdkBoolFalse = jsBoolFalse ? 1n : 0n

        expect(sdkBoolTrue).toBe(1n)
        expect(sdkBoolFalse).toBe(0n)

        // Verify they can be used with prepareIT
        const sender = createTestSender()
        expect(() => prepareIT(sdkBoolTrue, sender, TEST_CONSTANTS.CONTRACT_ADDRESS, TEST_CONSTANTS.FUNCTION_SELECTOR)).not.toThrow()
        expect(() => prepareIT(sdkBoolFalse, sender, TEST_CONSTANTS.CONTRACT_ADDRESS, TEST_CONSTANTS.FUNCTION_SELECTOR)).not.toThrow()
    })
})
