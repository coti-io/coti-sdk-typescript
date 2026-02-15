import { Wallet, recoverAddress, solidityPackedKeccak256, hexlify } from 'ethers'
import {
    prepareIT,
    prepareIT256,
    buildStringInputText,
    signInputText
} from '../../src'

/**
 * Signature Tampering Tests - TESTS.md Recommendation #7
 * 
 * These tests verify that signatures become invalid when any of the
 * signed parameters (contractAddress, functionSelector, ciphertext)
 * are modified after signing. This validates the security guarantees
 * of the signature scheme used in the SDK.
 */

// Load test constants from environment variables
const TEST_CONSTANTS = {
    PRIVATE_KEY: process.env.TEST_PRIVATE_KEY || '',
    USER_KEY: process.env.TEST_USER_KEY || '',
    CONTRACT_ADDRESS: '0x0000000000000000000000000000000000000001',
    FUNCTION_SELECTOR: '0x11223344'
}

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
 * Helper: recovers the signer address from a 65-byte signature
 * and the keccak256 message hash.
 */
function recoverSigner(messageHash: string, signature: Uint8Array): string {
    const r = hexlify(signature.slice(0, 32))
    const s = hexlify(signature.slice(32, 64))
    const v = signature[64] + 27
    return recoverAddress(messageHash, { r, s, v }).toLowerCase()
}

describe('Integration: Signature Tampering Detection', () => {
    const sender = createTestSender()
    const expectedAddress = sender.wallet.address.toLowerCase()

    describe('prepareIT signature integrity', () => {
        test('signature verifies with original parameters', () => {
            const plaintext = 12345n
            const { ciphertext, signature } = prepareIT(
                plaintext, sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Reconstruct the message that was signed
            const messageHash = solidityPackedKeccak256(
                ['address', 'address', 'bytes4', 'uint256'],
                [sender.wallet.address, TEST_CONSTANTS.CONTRACT_ADDRESS, TEST_CONSTANTS.FUNCTION_SELECTOR, ciphertext]
            )

            const recovered = recoverSigner(messageHash, signature as Uint8Array)
            expect(recovered).toBe(expectedAddress)
        })

        test('signature fails verification when contractAddress is tampered', () => {
            const plaintext = 12345n
            const { ciphertext, signature } = prepareIT(
                plaintext, sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Tamper: use a different contract address for verification
            const tamperedAddress = '0x0000000000000000000000000000000000000002'
            const tamperedHash = solidityPackedKeccak256(
                ['address', 'address', 'bytes4', 'uint256'],
                [sender.wallet.address, tamperedAddress, TEST_CONSTANTS.FUNCTION_SELECTOR, ciphertext]
            )

            const recovered = recoverSigner(tamperedHash, signature as Uint8Array)
            expect(recovered).not.toBe(expectedAddress)
        })

        test('signature fails verification when functionSelector is tampered', () => {
            const plaintext = 12345n
            const { ciphertext, signature } = prepareIT(
                plaintext, sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Tamper: use a different function selector for verification
            const tamperedSelector = '0x55667788'
            const tamperedHash = solidityPackedKeccak256(
                ['address', 'address', 'bytes4', 'uint256'],
                [sender.wallet.address, TEST_CONSTANTS.CONTRACT_ADDRESS, tamperedSelector, ciphertext]
            )

            const recovered = recoverSigner(tamperedHash, signature as Uint8Array)
            expect(recovered).not.toBe(expectedAddress)
        })

        test('signature fails verification when ciphertext is tampered', () => {
            const plaintext = 12345n
            const { ciphertext, signature } = prepareIT(
                plaintext, sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Tamper: modify the ciphertext value
            const tamperedCiphertext = ciphertext + 1n
            const tamperedHash = solidityPackedKeccak256(
                ['address', 'address', 'bytes4', 'uint256'],
                [sender.wallet.address, TEST_CONSTANTS.CONTRACT_ADDRESS, TEST_CONSTANTS.FUNCTION_SELECTOR, tamperedCiphertext]
            )

            const recovered = recoverSigner(tamperedHash, signature as Uint8Array)
            expect(recovered).not.toBe(expectedAddress)
        })

        test('signature fails verification when sender address is tampered', () => {
            const plaintext = 12345n
            const { ciphertext, signature } = prepareIT(
                plaintext, sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            // Tamper: use a different sender address for verification
            const tamperedSender = '0x0000000000000000000000000000000000000099'
            const tamperedHash = solidityPackedKeccak256(
                ['address', 'address', 'bytes4', 'uint256'],
                [tamperedSender, TEST_CONSTANTS.CONTRACT_ADDRESS, TEST_CONSTANTS.FUNCTION_SELECTOR, ciphertext]
            )

            const recovered = recoverSigner(tamperedHash, signature as Uint8Array)
            expect(recovered).not.toBe(expectedAddress)
        })
    })

    describe('signInputText tampering detection', () => {
        test('signInputText produces valid signature for given parameters', () => {
            const ct = BigInt(99999)
            const signature = signInputText(
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR,
                ct
            )

            const messageHash = solidityPackedKeccak256(
                ['address', 'address', 'bytes4', 'uint256'],
                [sender.wallet.address, TEST_CONSTANTS.CONTRACT_ADDRESS, TEST_CONSTANTS.FUNCTION_SELECTOR, ct]
            )

            const recovered = recoverSigner(messageHash, signature)
            expect(recovered).toBe(expectedAddress)
        })

        test('signInputText result is invalid when any parameter is changed', () => {
            const ct = BigInt(99999)
            const signature = signInputText(
                sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR,
                ct
            )

            // Test with each parameter tampered individually
            const tamperCases = [
                { desc: 'tampered sender', args: ['0x0000000000000000000000000000000000000099', TEST_CONSTANTS.CONTRACT_ADDRESS, TEST_CONSTANTS.FUNCTION_SELECTOR, ct] },
                { desc: 'tampered contract', args: [sender.wallet.address, '0x0000000000000000000000000000000000000099', TEST_CONSTANTS.FUNCTION_SELECTOR, ct] },
                { desc: 'tampered selector', args: [sender.wallet.address, TEST_CONSTANTS.CONTRACT_ADDRESS, '0x99887766', ct] },
                { desc: 'tampered ciphertext', args: [sender.wallet.address, TEST_CONSTANTS.CONTRACT_ADDRESS, TEST_CONSTANTS.FUNCTION_SELECTOR, ct + 1n] },
            ] as const

            for (const { desc: _desc, args } of tamperCases) {
                const tamperedHash = solidityPackedKeccak256(
                    ['address', 'address', 'bytes4', 'uint256'],
                    args as any
                )
                const recovered = recoverSigner(tamperedHash, signature)
                expect(recovered).not.toBe(expectedAddress)
            }
        })
    })

    describe('prepareIT256 signature integrity', () => {
        test('prepareIT256 signatures differ when contractAddress changes', () => {
            const plaintext = 2n ** 200n

            const result1 = prepareIT256(
                plaintext, sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            const result2 = prepareIT256(
                plaintext, sender,
                '0x0000000000000000000000000000000000000002',
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            expect(result1.signature).not.toEqual(result2.signature)
        })

        test('prepareIT256 signatures differ when functionSelector changes', () => {
            const plaintext = 2n ** 200n

            const result1 = prepareIT256(
                plaintext, sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            const result2 = prepareIT256(
                plaintext, sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                '0x55667788'
            )

            expect(result1.signature).not.toEqual(result2.signature)
        })
    })

    describe('buildStringInputText signature integrity', () => {
        test('string signatures differ when contractAddress changes', () => {
            const plaintext = 'Hello, world!'

            const result1 = buildStringInputText(
                plaintext, sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            const result2 = buildStringInputText(
                plaintext, sender,
                '0x0000000000000000000000000000000000000002',
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            expect(result1.signature).not.toEqual(result2.signature)
        })

        test('string signatures differ when functionSelector changes', () => {
            const plaintext = 'Hello, world!'

            const result1 = buildStringInputText(
                plaintext, sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            const result2 = buildStringInputText(
                plaintext, sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                '0x55667788'
            )

            expect(result1.signature).not.toEqual(result2.signature)
        })

        test('string signatures differ when plaintext changes', () => {
            const result1 = buildStringInputText(
                'Hello', sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            const result2 = buildStringInputText(
                'World', sender,
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )

            expect(result1.signature).not.toEqual(result2.signature)
        })
    })
})
