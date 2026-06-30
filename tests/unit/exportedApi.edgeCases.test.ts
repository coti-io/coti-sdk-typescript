import forge from 'node-forge'
import { Wallet } from 'ethers'
import {
    binaryStringToBytes,
    buildInputText,
    buildItSignature,
    buildItUint256WithSigner,
    buildStringInputText,
    decrypt,
    decryptCtUint256,
    decryptUint256,
    encrypt,
    encryptNumber,
    encryptUint,
    encryptUint256,
    encodeKey,
    encodeString,
    encodeUint,
    decodeUint,
    generateRandomAesKeyBinaryString,
    generateRandomAesKeySizeNumber,
    isCtUint256Shape,
    isZeroCtUint256,
    normalizeCtPayload,
    prepareIT,
    prepareIT256,
    sign,
    signInputText
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
const SENDER = createTestSender()
const CONTRACT = TEST_CONSTANTS.CONTRACT_ADDRESS
const SELECTOR = TEST_CONSTANTS.FUNCTION_SELECTOR

describe('Exported API edge cases', () => {
    beforeEach(() => {
        (forge.random.getBytesSync as jest.Mock).mockReturnValue('ABCDEFGHIJKLMNOP')
    })

    describe('binaryStringToBytes / encodeString', () => {
        test.each([0, 1, 127, 128, 255])('round-trips byte value %i', (byte) => {
            const binary = String.fromCodePoint(byte)
            expect(binaryStringToBytes(binary)).toEqual(new Uint8Array([byte]))
            expect(encodeString(binary)).toEqual(binaryStringToBytes(binary))
        })

        test('handles empty binary string', () => {
            expect(binaryStringToBytes('')).toEqual(new Uint8Array([]))
        })

        test('handles multi-byte forge binary string', () => {
            const binary = String.fromCodePoint(1, 2, 3, 254, 255)
            expect(binaryStringToBytes(binary)).toEqual(new Uint8Array([1, 2, 3, 254, 255]))
        })
    })

    describe('generateRandomAesKeyBinaryString / generateRandomAesKeySizeNumber', () => {
        test('deprecated alias matches canonical export', () => {
            expect(generateRandomAesKeySizeNumber()).toBe(generateRandomAesKeyBinaryString())
        })
    })

    describe('encrypt / decrypt block primitives', () => {
        const key = encodeKey(AES_KEY)

        test('encrypt pads short plaintext with leading zeros', () => {
            const shortPlaintext = new Uint8Array([57]) // single byte "9"
            const { ciphertext, r } = encrypt(key, shortPlaintext)
            expect(ciphertext).toHaveLength(16)
            expect(r).toHaveLength(16)
            expect(decrypt(key, r, ciphertext)).toEqual(
                new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 57])
            )
        })

        test('encrypt accepts empty plaintext', () => {
            const { ciphertext, r } = encrypt(key, new Uint8Array())
            expect(decrypt(key, r, ciphertext)).toEqual(new Uint8Array(16))
        })

        test('encrypt accepts exactly 16-byte plaintext', () => {
            const plaintext = new Uint8Array(16).map((_, i) => i)
            const { ciphertext, r } = encrypt(key, plaintext)
            expect(decrypt(key, r, ciphertext)).toEqual(plaintext)
        })

        test('decrypt merges two 16-byte blocks into 32-byte plaintext', () => {
            const block1 = new Uint8Array(16).fill(1)
            const block2 = new Uint8Array(16).fill(2)
            const enc1 = encrypt(key, block1)
            const enc2 = encrypt(key, block2)
            const merged = decrypt(
                key,
                enc1.r,
                enc1.ciphertext,
                enc2.r,
                enc2.ciphertext
            )
            expect(merged).toEqual(new Uint8Array([...block1, ...block2]))
        })

        test('encryptNumber accepts Uint8Array random input', () => {
            const randomBytes = new Uint8Array(16).map((_, i) => i + 1)
            const encrypted = encryptNumber(randomBytes, key)
            expect(encrypted).toHaveLength(16)
        })
    })

    describe('encodeUint / decodeUint boundaries', () => {
        test.each([
            0n,
            1n,
            (2n ** 64n) - 1n,
            (2n ** 128n) - 1n
        ])('round-trips %s in 16-byte field', (value) => {
            expect(decodeUint(encodeUint(value))).toBe(value)
        })
    })

    describe('buildInputText / prepareIT boundaries', () => {
        test('buildInputText accepts 0 and max uint64', () => {
            expect(() => buildInputText(0n, SENDER, CONTRACT, SELECTOR)).not.toThrow()
            expect(() => buildInputText((2n ** 64n) - 1n, SENDER, CONTRACT, SELECTOR)).not.toThrow()
        })

        test('prepareIT accepts 0 and max uint128', () => {
            expect(() => prepareIT(0n, SENDER, CONTRACT, SELECTOR)).not.toThrow()
            expect(() => prepareIT((2n ** 128n) - 1n, SENDER, CONTRACT, SELECTOR)).not.toThrow()
        })

        test.each([
            ['buildInputText', () => buildInputText(-1n, SENDER, CONTRACT, SELECTOR)],
            ['prepareIT', () => prepareIT(-1n, SENDER, CONTRACT, SELECTOR)],
            ['prepareIT256', () => prepareIT256(-1n, SENDER, CONTRACT, SELECTOR)]
        ])('%s rejects negative plaintext', (_name, fn) => {
            expect(fn).toThrow(RangeError)
        })
    })

    describe('buildStringInputText edge cases', () => {
        test('handles empty string with no chunks', () => {
            const result = buildStringInputText('', SENDER, CONTRACT, SELECTOR)
            expect(result.ciphertext.value).toEqual([])
            expect(result.signature).toEqual([])
        })

        test('handles exactly one byte', () => {
            const result = buildStringInputText('a', SENDER, CONTRACT, SELECTOR)
            expect(result.ciphertext.value).toHaveLength(1)
        })

        test('handles exactly 8-byte UTF-8 chunk boundary', () => {
            const eightBytes = 'abcdefgh'
            const result = buildStringInputText(eightBytes, SENDER, CONTRACT, SELECTOR)
            expect(result.ciphertext.value).toHaveLength(1)
        })

        test('handles 9 bytes as two chunks', () => {
            const result = buildStringInputText('123456789', SENDER, CONTRACT, SELECTOR)
            expect(result.ciphertext.value).toHaveLength(2)
        })
    })

    describe('encryptUint256 encoding path boundary', () => {
        test('uses compact encoding at 128 bits', () => {
            const compact = encryptUint256((2n ** 128n) - 1n, AES_KEY)
            expect(decryptUint256(compact, AES_KEY)).toBe((2n ** 128n) - 1n)
        })

        test('uses full encoding at 129 bits', () => {
            const full = encryptUint256(2n ** 128n, AES_KEY)
            expect(decryptUint256(full, AES_KEY)).toBe(2n ** 128n)
        })
    })

    describe('normalizeCtPayload', () => {
        test('coerces numeric ctUint64 payloads', () => {
            expect(normalizeCtPayload(789, 'ctUint64')).toBe(789n)
        })

        test('rejects null ctUint64 payloads', () => {
            expect(() => normalizeCtPayload(null as any, 'ctUint64')).toThrow('Missing bigint value.')
        })

        test('rejects ctUint256 tuple with wrong length', () => {
            expect(() => normalizeCtPayload([1n] as any, 'ctUint256')).toThrow('Invalid ctUint256 payload.')
        })

        test('rejects ctUint256 object missing one field', () => {
            expect(() => normalizeCtPayload({ ciphertextHigh: 1n } as any, 'ctUint256')).toThrow(
                'Invalid ctUint256 payload.'
            )
        })

        test('rejects invalid inner ctUint256 field types', () => {
            expect(() =>
                normalizeCtPayload({ ciphertextHigh: {}, ciphertextLow: 0n } as any, 'ctUint256')
            ).toThrow('Invalid bigint value.')
        })
    })

    describe('isCtUint256Shape', () => {
        test.each([
            null,
            undefined,
            0n,
            'string',
            42,
            {},
            { ciphertextHigh: 1n },
            [1n],
            [1n, 2n, 3n],
            { high: { high: 1n }, low: { high: 2n, low: 3n } }
        ])('returns false for non-shape value %p', (value) => {
            expect(isCtUint256Shape(value)).toBe(false)
        })
    })

    describe('isZeroCtUint256', () => {
        test('treats scalar zero as zero', () => {
            expect(isZeroCtUint256(0n)).toBe(true)
            expect(isZeroCtUint256('0')).toBe(true)
        })

        test('returns false for invalid shapes', () => {
            expect(isZeroCtUint256({ invalid: true })).toBe(false)
            expect(isZeroCtUint256(null)).toBe(false)
        })

        test('returns false when only one flat part is zero', () => {
            expect(isZeroCtUint256({ ciphertextHigh: 0n, ciphertextLow: 1n })).toBe(false)
            expect(isZeroCtUint256([0n, 1n])).toBe(false)
        })

        test('returns false for nested shape with any non-zero limb', () => {
            expect(
                isZeroCtUint256({
                    high: { high: 0n, low: 0n },
                    low: { high: 1n, low: 0n }
                })
            ).toBe(false)
        })
    })

    describe('decryptCtUint256', () => {
        test('throws on invalid payload', () => {
            expect(() => decryptCtUint256({}, AES_KEY)).toThrow('Invalid ctUint256 payload.')
            expect(() => decryptCtUint256(null, AES_KEY)).toThrow('Invalid ctUint256 payload.')
        })

        test('accepts serialized string parts in flat tuple form', () => {
            const encrypted = encryptUint256(999n, AES_KEY)
            expect(
                decryptCtUint256(
                    [encrypted.ciphertextHigh.toString(), encrypted.ciphertextLow.toString()],
                    AES_KEY
                )
            ).toBe(999n)
        })
    })

    describe('buildItUint256WithSigner', () => {
        test('rejects out-of-range values via encryptUint256 validation', async () => {
            await expect(
                buildItUint256WithSigner({
                    value: 2n ** 256n,
                    aesKey: AES_KEY,
                    signerAddress: Wallet.createRandom().address,
                    contractAddress: CONTRACT,
                    functionSelector: SELECTOR,
                    signMessage: jest.fn()
                })
            ).rejects.toThrow(RangeError)
        })

        test('rejects invalid AES key', async () => {
            await expect(
                buildItUint256WithSigner({
                    value: 1n,
                    aesKey: 'not-a-key',
                    signerAddress: Wallet.createRandom().address,
                    contractAddress: CONTRACT,
                    functionSelector: SELECTOR,
                    signMessage: jest.fn()
                })
            ).rejects.toThrow('Invalid AES key')
        })
    })

    describe('sign / signInputText / buildItSignature', () => {
        test('sign produces 65-byte signature for hex message', () => {
            const wallet = Wallet.createRandom()
            const sig = sign('0x' + '11'.repeat(32), wallet.privateKey)
            expect(sig).toHaveLength(65)
        })

        test('signInputText returns 65-byte signature', () => {
            const wallet = Wallet.createRandom()
            const sig = signInputText(
                { wallet, userKey: AES_KEY },
                CONTRACT,
                SELECTOR,
                123n
            )
            expect(sig).toHaveLength(65)
        })

        test('buildItSignature compares signer addresses case-insensitively', () => {
            const wallet = Wallet.createRandom()

            expect(() =>
                buildItSignature(
                    wallet.address.toLowerCase(),
                    CONTRACT,
                    SELECTOR,
                    1n,
                    wallet.privateKey
                )
            ).not.toThrow()
        })
    })

    describe('encryptUint edge cases', () => {
        test('accepts number-like bigint inputs through coercion', () => {
            expect(encryptUint(BigInt(7), AES_KEY)).toBe(encryptUint(7n, AES_KEY))
        })

        test('rejects 65-bit boundary', () => {
            expect(() => encryptUint(2n ** 64n, AES_KEY)).toThrow(RangeError)
        })
    })
})
