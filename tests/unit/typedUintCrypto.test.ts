import forge from 'node-forge'
import { getBytes, solidityPacked, Wallet } from 'ethers'
import {
    buildItUint256WithSigner,
    buildInputText,
    decryptCtUint256,
    decryptUint,
    decryptUint256,
    encryptUint,
    encryptUint256,
    isCtUint256Shape,
    isZeroCtUint256,
    normalizeCtPayload,
    prepareIT,
    prepareIT256
} from '../../src'
import { createTestSender, TEST_CONSTANTS } from '../helpers'

jest.mock('node-forge', () => {
    const defaultForge = jest.requireActual('node-forge')

    return {
        ...defaultForge,
        random: {
            ...defaultForge.random,
            getBytesSync: jest.fn()
        }
    }
})

const AES_KEY = TEST_CONSTANTS.USER_KEY
const CONTRACT_ADDRESS = TEST_CONSTANTS.CONTRACT_ADDRESS
const FUNCTION_SELECTOR = TEST_CONSTANTS.FUNCTION_SELECTOR

describe('typed uint ciphertext helpers', () => {
    beforeEach(() => {
        (forge.random.getBytesSync as jest.Mock).mockReturnValue('ABCDEFGHIJKLMNOP')
    })

    describe('encryptUint', () => {
        test.each([
            0n,
            42n,
            (2n ** 64n) - 1n
        ])('round-trips %s through decryptUint', (value) => {
            const ciphertext = encryptUint(value, AES_KEY)

            expect(decryptUint(ciphertext, AES_KEY)).toBe(value)
        })

        test('matches buildInputText ciphertext for the same random block', () => {
            const value = 12345n
            const encrypted = encryptUint(value, AES_KEY)
            const { ciphertext } = buildInputText(
                value,
                createTestSender(),
                CONTRACT_ADDRESS,
                FUNCTION_SELECTOR
            )

            expect(encrypted).toBe(ciphertext)
        })

        test('rejects values outside uint64', () => {
            expect(() => encryptUint(2n ** 64n, AES_KEY)).toThrow(RangeError)
            expect(() => encryptUint(-1n, AES_KEY)).toThrow(RangeError)
        })
    })

    describe('uint IT builder limits', () => {
        test('keeps buildInputText at 64 bits and prepareIT at 128 bits', () => {
            const value = 2n ** 64n
            const sender = createTestSender()

            expect(() =>
                buildInputText(value, sender, CONTRACT_ADDRESS, FUNCTION_SELECTOR)
            ).toThrow('Plaintext size must be 64 bits or smaller.')

            const { ciphertext } = prepareIT(value, sender, CONTRACT_ADDRESS, FUNCTION_SELECTOR)
            expect(decryptUint(ciphertext, AES_KEY)).toBe(value)
        })
    })

    describe('encryptUint256', () => {
        test.each([
            0n,
            42n,
            (2n ** 128n) - 1n,
            2n ** 200n,
            (2n ** 256n) - 1n
        ])('round-trips %s through decryptUint256', (value) => {
            const ciphertext = encryptUint256(value, AES_KEY)

            expect(decryptUint256(ciphertext, AES_KEY)).toBe(value)
        })

        test.each([
            12345n,
            2n ** 200n
        ])('matches prepareIT256 ciphertext for %s', (value) => {
            const encrypted = encryptUint256(value, AES_KEY)
            const { ciphertext } = prepareIT256(
                value,
                createTestSender(),
                CONTRACT_ADDRESS,
                FUNCTION_SELECTOR
            )

            expect(encrypted).toEqual(ciphertext)
        })

        test('rejects values outside uint256', () => {
            expect(() => encryptUint256(2n ** 256n, AES_KEY)).toThrow(RangeError)
            expect(() => encryptUint256(-1n, AES_KEY)).toThrow(RangeError)
        })

        test('switches encoding at the 128/129-bit boundary', () => {
            expect(decryptUint256(encryptUint256((2n ** 128n) - 1n, AES_KEY), AES_KEY)).toBe(
                (2n ** 128n) - 1n
            )
            expect(decryptUint256(encryptUint256(2n ** 128n, AES_KEY), AES_KEY)).toBe(2n ** 128n)
        })
    })

    describe('normalizeCtPayload', () => {
        test('normalizes ctUint64 payloads', () => {
            expect(normalizeCtPayload('123', 'ctUint64')).toBe(123n)
            expect(normalizeCtPayload(456n, 'ctUint64')).toBe(456n)
        })

        test('rejects object payloads for ctUint64', () => {
            expect(() => normalizeCtPayload({} as any, 'ctUint64')).toThrow(
                'Invalid bigint value.'
            )
        })

        test('normalizes ctUint256 payloads', () => {
            expect(
                normalizeCtPayload(
                    { ciphertextHigh: '1', ciphertextLow: 2n },
                    'ctUint256'
                )
            ).toEqual({ ciphertextHigh: 1n, ciphertextLow: 2n })
            expect(normalizeCtPayload(['3', 4n], 'ctUint256')).toEqual({
                ciphertextHigh: 3n,
                ciphertextLow: 4n
            })
        })

        test('rejects malformed ctUint256 payloads', () => {
            expect(() => normalizeCtPayload({} as any, 'ctUint256')).toThrow(
                'Invalid ctUint256 payload.'
            )
            expect(() => normalizeCtPayload('123' as any, 'ctUint256')).toThrow(
                'Invalid ctUint256 payload.'
            )
            expect(() =>
                normalizeCtPayload(
                    {
                        high: { high: 1n, low: 2n },
                        low: { high: 3n, low: 4n }
                    } as any,
                    'ctUint256'
                )
            ).toThrow('Invalid ctUint256 payload.')
        })
    })

    describe('ctUint256 shape helpers', () => {
        test('detects flat, positional, and nested ctUint256 shapes', () => {
            expect(isCtUint256Shape({ ciphertextHigh: 1n, ciphertextLow: 2n })).toBe(true)
            expect(isCtUint256Shape([1n, 2n])).toBe(true)
            expect(
                isCtUint256Shape({
                    high: { high: 1n, low: 2n },
                    low: { high: 3n, low: 4n }
                })
            ).toBe(true)
            expect(isCtUint256Shape({ invalid: true })).toBe(false)
        })

        test('detects zero ctUint256 values', () => {
            expect(isZeroCtUint256({ ciphertextHigh: 0n, ciphertextLow: 0n })).toBe(true)
            expect(isZeroCtUint256([0n, 0n])).toBe(true)
            expect(
                isZeroCtUint256({
                    high: { high: 0n, low: 0n },
                    low: { high: 0n, low: 0n }
                })
            ).toBe(true)
            expect(isZeroCtUint256({ ciphertextHigh: 1n, ciphertextLow: 0n })).toBe(false)
        })

        test('decrypts flat and nested ctUint256 shapes', () => {
            const flat = encryptUint256(12345n, AES_KEY)
            expect(decryptCtUint256(flat, AES_KEY)).toBe(12345n)
            expect(decryptCtUint256([flat.ciphertextHigh, flat.ciphertextLow], AES_KEY)).toBe(12345n)

            const nested = {
                high: {
                    high: encryptUint(1n, AES_KEY),
                    low: encryptUint(2n, AES_KEY)
                },
                low: {
                    high: encryptUint(3n, AES_KEY),
                    low: encryptUint(4n, AES_KEY)
                }
            }
            const expected = (1n << 192n) + (2n << 128n) + (3n << 64n) + 4n
            expect(decryptCtUint256(nested, AES_KEY)).toBe(expected)
        })
    })

    describe('buildItUint256WithSigner', () => {
        test('builds a signed flat itUint256 with signer callback', async () => {
            const signerAddress = Wallet.createRandom().address
            const signature = '0x1234'
            const signMessage = jest.fn().mockResolvedValue(signature)

            const result = await buildItUint256WithSigner({
                value: 12345n,
                aesKey: AES_KEY,
                signerAddress,
                contractAddress: CONTRACT_ADDRESS,
                functionSelector: FUNCTION_SELECTOR,
                signMessage
            })

            expect(result.ciphertext).toEqual(encryptUint256(12345n, AES_KEY))
            expect(result.signature).toBe(signature)
            expect(signMessage).toHaveBeenCalledWith(
                getBytes(
                    solidityPacked(
                        ['address', 'address', 'bytes4', 'uint256', 'uint256'],
                        [
                            signerAddress,
                            CONTRACT_ADDRESS,
                            FUNCTION_SELECTOR,
                            result.ciphertext.ciphertextHigh,
                            result.ciphertext.ciphertextLow
                        ]
                    )
                )
            )
        })

        test('uses the browser-signer payload, not prepareIT256 raw-bytes signing', async () => {
            const sender = createTestSender()
            const value = 12345n
            const signMessage = jest.fn().mockResolvedValue('0x1234')
            const prepared = prepareIT256(value, sender, CONTRACT_ADDRESS, FUNCTION_SELECTOR)

            await buildItUint256WithSigner({
                value,
                aesKey: AES_KEY,
                signerAddress: sender.wallet.address,
                contractAddress: CONTRACT_ADDRESS,
                functionSelector: FUNCTION_SELECTOR,
                signMessage
            })

            const signerPayload = signMessage.mock.calls[0][0]
            const prepareItCiphertextBytes = new Uint8Array([
                ...getBytes('0x' + prepared.ciphertext.ciphertextHigh.toString(16).padStart(64, '0')),
                ...getBytes('0x' + prepared.ciphertext.ciphertextLow.toString(16).padStart(64, '0'))
            ])

            expect(signerPayload).not.toEqual(prepareItCiphertextBytes)
        })
    })
})
