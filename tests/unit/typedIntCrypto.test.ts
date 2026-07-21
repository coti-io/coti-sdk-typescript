import forge from 'node-forge'
import {
    decryptInt256,
    decryptUint256,
    encryptInt256,
    encryptUint256,
    prepareSignedIT256
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

describe('typed int256 ciphertext helpers', () => {
    beforeEach(() => {
        (forge.random.getBytesSync as jest.Mock).mockReturnValue('ABCDEFGHIJKLMNOP')
    })

    describe('encryptInt256 / decryptInt256', () => {
        test.each([
            0n,
            1n,
            -1n,
            42n,
            -42n,
            (2n ** 255n) - 1n,
            -(2n ** 255n)
        ])('round-trips %s', (value) => {
            const ciphertext = encryptInt256(value, AES_KEY)
            expect(decryptInt256(ciphertext, AES_KEY)).toBe(value)
        })

        test('negative plaintext shares wire format with uint two\'s complement', () => {
            const signed = encryptInt256(-1n, AES_KEY)
            expect(decryptUint256(signed, AES_KEY)).toBe((1n << 256n) - 1n)
            expect(decryptInt256(encryptUint256((1n << 256n) - 1n, AES_KEY), AES_KEY)).toBe(-1n)
        })

        test('rejects values outside int256', () => {
            expect(() => encryptInt256(2n ** 255n, AES_KEY)).toThrow(RangeError)
            expect(() => encryptInt256(-(2n ** 255n) - 1n, AES_KEY)).toThrow(RangeError)
        })
    })

    describe('prepareSignedIT256', () => {
        test.each([
            -1n,
            0n,
            12345n,
            -(2n ** 200n)
        ])('round-trips %s through decryptInt256', (value) => {
            const { ciphertext } = prepareSignedIT256(
                value,
                createTestSender(),
                CONTRACT_ADDRESS,
                FUNCTION_SELECTOR
            )
            expect(decryptInt256(ciphertext, AES_KEY)).toBe(value)
        })

        test('matches encryptInt256 ciphertext for the same random block', () => {
            const value = -99n
            const encrypted = encryptInt256(value, AES_KEY)
            const { ciphertext } = prepareSignedIT256(
                value,
                createTestSender(),
                CONTRACT_ADDRESS,
                FUNCTION_SELECTOR
            )
            expect(encrypted).toEqual(ciphertext)
        })

        test('rejects values outside int256', () => {
            const sender = createTestSender()
            expect(() =>
                prepareSignedIT256(2n ** 255n, sender, CONTRACT_ADDRESS, FUNCTION_SELECTOR)
            ).toThrow(RangeError)
        })
    })
})
