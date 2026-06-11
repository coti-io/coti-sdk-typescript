import { Wallet, recoverAddress, solidityPackedKeccak256, getBytes, hexlify } from 'ethers'
import {
    buildInputText,
    buildItSignature,
    decryptUint,
    normalizeAesKey,
    signInputText
} from '../../src'

const AES_KEY = '0123456789abcdef0123456789abcdef' // 32 hex chars (128-bit)
const AES_KEY_256 = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' // 64 hex chars
const CONTRACT_ADDRESS = '0x0000000000000000000000000000000000000001'
const FUNCTION_SELECTOR = '0x11223344'

describe('normalizeAesKey', () => {
    test('strips the 0x prefix', () => {
        expect(normalizeAesKey('0x' + AES_KEY)).toBe(AES_KEY)
    })

    test('lowercases the key', () => {
        expect(normalizeAesKey(AES_KEY.toUpperCase())).toBe(AES_KEY)
    })

    test('accepts a 32-char (128-bit) key', () => {
        expect(normalizeAesKey(AES_KEY)).toBe(AES_KEY)
    })

    test('rejects a 64-char (256-bit) key since COTI uses 128-bit AES', () => {
        expect(() => normalizeAesKey(AES_KEY_256)).toThrow('expected 32 hex characters')
    })

    test('throws on non-hexadecimal characters', () => {
        expect(() => normalizeAesKey('g'.repeat(32))).toThrow('non-hexadecimal')
    })

    test('throws on invalid length', () => {
        expect(() => normalizeAesKey('abcdef')).toThrow('expected 32 hex characters')
    })

    test('throws when key is undefined', () => {
        expect(() => normalizeAesKey(undefined)).toThrow('AES key is required')
    })

    test('throws when key is null', () => {
        expect(() => normalizeAesKey(null)).toThrow('AES key is required')
    })

    test('throws when key is an empty string', () => {
        expect(() => normalizeAesKey('')).toThrow('AES key is required')
    })
})

describe('decryptUint (merged zero-handling + key normalization)', () => {
    function buildCiphertext(plaintext: bigint): bigint {
        const wallet = Wallet.createRandom()
        const { ciphertext } = buildInputText(
            plaintext,
            { wallet, userKey: AES_KEY },
            CONTRACT_ADDRESS,
            FUNCTION_SELECTOR
        )
        return ciphertext
    }

    test('returns 0n for a zero ciphertext without touching the key', () => {
        expect(decryptUint(0n, 'not-a-valid-key')).toBe(0n)
    })

    test('round-trips a small plaintext value', () => {
        const ciphertext = buildCiphertext(12345n)
        expect(decryptUint(ciphertext, AES_KEY)).toBe(12345n)
    })

    test('accepts a 0x-prefixed key', () => {
        const ciphertext = buildCiphertext(777n)
        expect(decryptUint(ciphertext, '0x' + AES_KEY)).toBe(777n)
    })

    test('throws on an invalid key', () => {
        const ciphertext = buildCiphertext(42n)
        expect(() => decryptUint(ciphertext, 'xyz')).toThrow()
    })
})

describe('buildItSignature', () => {
    test('produces a 65-byte hex signature', () => {
        const wallet = Wallet.createRandom()
        const signature = buildItSignature(
            wallet.address,
            CONTRACT_ADDRESS,
            FUNCTION_SELECTOR,
            12345n,
            wallet.privateKey
        )
        expect(typeof signature).toBe('string')
        // 0x + 65 bytes * 2 hex chars = 132 characters
        expect(signature.length).toBe(132)
    })

    test('recovers the correct signer address', () => {
        const wallet = Wallet.createRandom()
        const ciphertext = 12345n
        const signature = buildItSignature(
            wallet.address,
            CONTRACT_ADDRESS,
            FUNCTION_SELECTOR,
            ciphertext,
            wallet.privateKey
        )

        const digest = solidityPackedKeccak256(
            ['address', 'address', 'bytes4', 'uint256'],
            [wallet.address, CONTRACT_ADDRESS, FUNCTION_SELECTOR, ciphertext]
        )

        const bytes = getBytes(signature)
        const r = hexlify(bytes.slice(0, 32))
        const s = hexlify(bytes.slice(32, 64))
        const v = bytes[64] + 27

        const recovered = recoverAddress(digest, { r, s, v })
        expect(recovered.toLowerCase()).toBe(wallet.address.toLowerCase())
    })

    test('matches the bytes produced by signInputText for the same inputs', () => {
        const wallet = Wallet.createRandom()
        const ciphertext = 98765n

        const fromBuild = buildItSignature(
            wallet.address,
            CONTRACT_ADDRESS,
            FUNCTION_SELECTOR,
            ciphertext,
            wallet.privateKey
        )

        const fromSignInputText = hexlify(
            signInputText(
                { wallet, userKey: '' },
                CONTRACT_ADDRESS,
                FUNCTION_SELECTOR,
                ciphertext
            )
        )

        expect(fromBuild).toBe(fromSignInputText)
    })

    test('throws when signerAddress does not match the private key', () => {
        const wallet = Wallet.createRandom()
        const otherWallet = Wallet.createRandom()

        expect(() =>
            buildItSignature(
                otherWallet.address,
                CONTRACT_ADDRESS,
                FUNCTION_SELECTOR,
                12345n,
                wallet.privateKey
            )
        ).toThrow('does not match the address derived from privateKey')
    })
})
