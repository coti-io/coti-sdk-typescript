import {
    bigintToBytesBE,
    bytesToBigint,
    bytesToHex,
    ciphertextBytesToCtUint256,
    CT_SIZE,
    ctUint256ToBytes,
    ctUintToBytes,
    HEX_BASE
} from '../../src/bytes'

describe('bytes', () => {
    describe('HEX_BASE', () => {
        test('is 16', () => {
            expect(HEX_BASE).toBe(16)
        })
    })

    describe('bigintToBytesBE', () => {
        test.each([
            [0n, 1, '00'],
            [1n, 1, '01'],
            [255n, 1, 'ff'],
            [42n, 4, '0000002a'],
            [0n, 16, '00'.repeat(16)],
            [1n, 16, '00'.repeat(15) + '01'],
            [(2n ** 64n) - 1n, 8, 'ffffffffffffffff'],
            [(2n ** 128n) - 1n, 16, 'ff'.repeat(16)]
        ] as const)('encodes %s into %i bytes as %s', (value, width, expectedHex) => {
            const bytes = bigintToBytesBE(value, width)
            expect(bytes).toHaveLength(width)
            expect(bytesToHex(bytes)).toBe(expectedHex)
        })

        test('returns independent buffer slices', () => {
            const bytes = bigintToBytesBE(1n, 4)
            bytes[3] = 0
            expect(bytesToHex(bigintToBytesBE(1n, 4))).toBe('00000001')
        })
    })

    describe('bytesToBigint', () => {
        test.each([
            [new Uint8Array([0]), 0n],
            [new Uint8Array([1]), 1n],
            [new Uint8Array([0, 0, 0, 1]), 1n],
            [new Uint8Array([255]), 255n],
            [new Uint8Array([0xff, 0xff, 0xff, 0xff]), 0xffffffffn]
        ])('decodes %j to %s', (bytes, expected) => {
            expect(bytesToBigint(bytes)).toBe(expected)
        })

        test('throws for empty byte array', () => {
            expect(() => bytesToBigint(new Uint8Array())).toThrow(SyntaxError)
        })
    })

    describe('bytesToHex', () => {
        test.each([
            [new Uint8Array([]), ''],
            [new Uint8Array([0]), '00'],
            [new Uint8Array([10]), '0a'],
            [new Uint8Array([255]), 'ff'],
            [new Uint8Array([0x4b, 0x04, 0x18, 0xc1]), '4b0418c1']
        ])('encodes %j to %s', (bytes, expected) => {
            expect(bytesToHex(bytes)).toBe(expected)
        })
    })

    describe('ctUintToBytes', () => {
        test('always produces CT_SIZE bytes', () => {
            expect(ctUintToBytes(0n)).toHaveLength(CT_SIZE)
            expect(ctUintToBytes(12345n)).toHaveLength(CT_SIZE)
            expect(ctUintToBytes((2n ** 256n) - 1n)).toHaveLength(CT_SIZE)
        })

        test('round-trips through bytesToBigint for values fitting in CT_SIZE bytes', () => {
            const value = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefn
            expect(bytesToBigint(ctUintToBytes(value))).toBe(value)
        })
    })

    describe('ctUint256ToBytes / ciphertextBytesToCtUint256', () => {
        test('concatenates high and low ctUint parts', () => {
            const ct = {
                ciphertextHigh: 1n,
                ciphertextLow: 2n
            }
            const bytes = ctUint256ToBytes(ct)
            expect(bytes).toHaveLength(CT_SIZE * 2)
            expect(bytes.subarray(0, CT_SIZE)).toEqual(ctUintToBytes(1n))
            expect(bytes.subarray(CT_SIZE)).toEqual(ctUintToBytes(2n))
        })

        test('round-trips through ciphertextBytesToCtUint256', () => {
            const ct = {
                ciphertextHigh: (2n ** 128n) - 1n,
                ciphertextLow: 42n
            }
            const roundTripped = ciphertextBytesToCtUint256(ctUint256ToBytes(ct))
            expect(roundTripped).toEqual(ct)
        })

        test('splits 64-byte buffer at CT_SIZE boundary', () => {
            const high = 0x1111111111111111111111111111111111111111111111111111111111111111n
            const low = 0x2222222222222222222222222222222222222222222222222222222222222222n
            const bytes = ctUint256ToBytes({ ciphertextHigh: high, ciphertextLow: low })
            expect(ciphertextBytesToCtUint256(bytes)).toEqual({
                ciphertextHigh: high,
                ciphertextLow: low
            })
        })

        test('handles zero ctUint256 parts', () => {
            const bytes = ctUint256ToBytes({ ciphertextHigh: 0n, ciphertextLow: 0n })
            expect(bytes.every((b) => b === 0)).toBe(true)
            expect(ciphertextBytesToCtUint256(bytes)).toEqual({
                ciphertextHigh: 0n,
                ciphertextLow: 0n
            })
        })
    })
})
