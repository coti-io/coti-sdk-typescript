import { Wallet } from 'ethers'
import {
    encrypt,
    decrypt,
    encryptNumber,
    encodeKey,
    encodeUint,
    decodeUint,
    decryptUint,
    decryptUint256,
    decryptString,
    decryptRSA,
    recoverUserKey,
    prepareIT,
    prepareIT256,
    buildStringInputText
} from '../../src'

// Test fixtures
const VALID_AES_KEY = new Uint8Array([75, 4, 24, 193, 84, 61, 190, 112, 242, 21, 23, 91, 205, 223, 172, 66])
const VALID_PLAINTEXT = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 57])
const VALID_R = new Uint8Array([65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80])
const VALID_CIPHERTEXT = new Uint8Array([127, 171, 102, 2, 146, 178, 103, 87, 65, 62, 192, 34, 86, 183, 64, 25])
const VALID_USER_KEY = '4b0418c1543dbe70f215175bcddfac42'
const VALID_PRIVATE_KEY = '0x526c9f9fe2fc41fb30fd0dbba1d4d76d774030166ef9f819b361046f5a5b4a34'

// Load test constants from environment variables
const TEST_CONSTANTS = {
    PRIVATE_KEY: process.env.TEST_PRIVATE_KEY || VALID_PRIVATE_KEY,
    USER_KEY: process.env.TEST_USER_KEY || VALID_USER_KEY,
    CONTRACT_ADDRESS: process.env.TEST_CONTRACT_ADDRESS || '0x0000000000000000000000000000000000000001',
    FUNCTION_SELECTOR: process.env.TEST_FUNCTION_SELECTOR || '0x11223344'
}

function createTestSender() {
    return {
        wallet: new Wallet(TEST_CONSTANTS.PRIVATE_KEY),
        userKey: TEST_CONSTANTS.USER_KEY
    }
}

describe('Unit: Error Handling', () => {
    describe('encrypt error cases', () => {
        test('throws RangeError when plaintext exceeds 16 bytes', () => {
            const largePlaintext = new Uint8Array(17) // 17 bytes > 16 bytes
            expect(() => encrypt(VALID_AES_KEY, largePlaintext)).toThrow(RangeError)
            expect(() => encrypt(VALID_AES_KEY, largePlaintext)).toThrow('Plaintext size must be 128 bits or smaller.')
        })

        test('throws RangeError when key length is not 16 bytes', () => {
            const wrongKey = new Uint8Array(15) // 15 bytes < 16 bytes
            expect(() => encrypt(wrongKey, VALID_PLAINTEXT)).toThrow(RangeError)
        })
    })

    describe('decrypt error cases', () => {
        test('throws RangeError when ciphertext length is not 16 bytes', () => {
            const wrongCiphertext = new Uint8Array(15)
            expect(() => decrypt(VALID_AES_KEY, VALID_R, wrongCiphertext)).toThrow(RangeError)
            expect(() => decrypt(VALID_AES_KEY, VALID_R, wrongCiphertext)).toThrow('Ciphertext size must be 128 bits.')
        })

        test('throws RangeError when key length is not 16 bytes', () => {
            const wrongKey = new Uint8Array(15)
            expect(() => decrypt(wrongKey, VALID_R, VALID_CIPHERTEXT)).toThrow(RangeError)
            expect(() => decrypt(wrongKey, VALID_R, VALID_CIPHERTEXT)).toThrow('Key size must be 128 bits.')
        })

        test('throws RangeError when random length is not 16 bytes', () => {
            const wrongR = new Uint8Array(15)
            expect(() => decrypt(VALID_AES_KEY, wrongR, VALID_CIPHERTEXT)).toThrow(RangeError)
            expect(() => decrypt(VALID_AES_KEY, wrongR, VALID_CIPHERTEXT)).toThrow('Random size must be 128 bits.')
        })

        test('throws RangeError when r2 is provided but ciphertext2 is null', () => {
            expect(() => decrypt(VALID_AES_KEY, VALID_R, VALID_CIPHERTEXT, VALID_R, null)).toThrow(RangeError)
            expect(() => decrypt(VALID_AES_KEY, VALID_R, VALID_CIPHERTEXT, VALID_R, null)).toThrow('Ciphertext2 is required.')
        })

        test('throws RangeError when ciphertext2 is provided but r2 is null', () => {
            expect(() => decrypt(VALID_AES_KEY, VALID_R, VALID_CIPHERTEXT, null, VALID_CIPHERTEXT)).toThrow(RangeError)
            expect(() => decrypt(VALID_AES_KEY, VALID_R, VALID_CIPHERTEXT, null, VALID_CIPHERTEXT)).toThrow('Random2 is required.')
        })

        test('throws RangeError when r2 length is not 16 bytes', () => {
            const wrongR2 = new Uint8Array(15)
            expect(() => decrypt(VALID_AES_KEY, VALID_R, VALID_CIPHERTEXT, wrongR2, VALID_CIPHERTEXT)).toThrow(RangeError)
            expect(() => decrypt(VALID_AES_KEY, VALID_R, VALID_CIPHERTEXT, wrongR2, VALID_CIPHERTEXT)).toThrow('Random2 size must be 128 bits')
        })

        test('throws RangeError when ciphertext2 length is not 16 bytes', () => {
            const wrongCiphertext2 = new Uint8Array(15)
            expect(() => decrypt(VALID_AES_KEY, VALID_R, VALID_CIPHERTEXT, VALID_R, wrongCiphertext2)).toThrow(RangeError)
            expect(() => decrypt(VALID_AES_KEY, VALID_R, VALID_CIPHERTEXT, VALID_R, wrongCiphertext2)).toThrow('Ciphertext2 size must be 128 bits')
        })
    })

    describe('encryptNumber error cases', () => {
        test('throws RangeError when key length is not 16 bytes', () => {
            const wrongKey = new Uint8Array(15)
            expect(() => encryptNumber('ABCDEFGHIJKLMNOP', wrongKey)).toThrow(RangeError)
            expect(() => encryptNumber('ABCDEFGHIJKLMNOP', wrongKey)).toThrow('Key size must be 128 bits.')
        })
    })

    describe('encodeKey error cases', () => {
        test('produces incorrect result when user key length is not 32 hex characters', () => {
            const shortKey = '1234567890123456789012345678901' // 31 chars
            const result = encodeKey(shortKey)
            // Function doesn't throw, but produces incorrect result (last byte is incomplete)
            expect(result).toBeInstanceOf(Uint8Array)
            expect(result.length).toBe(16)
        })

        test('produces incorrect result when user key has invalid hex characters', () => {
            const invalidKey = '1234567890123456789012345678901g' // 'g' is invalid hex
            const result = encodeKey(invalidKey)
            // Function doesn't throw, but produces incorrect values
            // parseInt('1g', 16) returns 1 (stops at invalid char), so result[15] = 1
            expect(result).toBeInstanceOf(Uint8Array)
            expect(result.length).toBe(16)
            // The function processes what it can, invalid hex is handled gracefully
            expect(result[15]).toBe(1) // '1g' parses as '1'
        })

        test('produces zero-filled array when user key is empty', () => {
            const result = encodeKey('')
            // Function doesn't throw, but produces zeros
            expect(result).toBeInstanceOf(Uint8Array)
            expect(result.length).toBe(16)
            expect(result.every(b => b === 0)).toBe(true)
        })
    })

    describe('prepareIT error cases', () => {
        test('throws RangeError when plaintext exceeds 128 bits', () => {
            const largePlaintext = 2n ** 128n // 129 bits
            expect(() => prepareIT(
                largePlaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )).toThrow(RangeError)
            expect(() => prepareIT(
                largePlaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )).toThrow('Plaintext size must be 128 bits or smaller')
        })

        test('works correctly with exactly 128 bits', () => {
            const exactly128Bits = (2n ** 128n) - 1n
            expect(() => prepareIT(
                exactly128Bits,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )).not.toThrow()
        })
    })

    describe('prepareIT256 error cases', () => {
        test('throws RangeError when plaintext exceeds 256 bits', () => {
            const largePlaintext = 2n ** 256n // 257 bits
            expect(() => prepareIT256(
                largePlaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )).toThrow(RangeError)
            expect(() => prepareIT256(
                largePlaintext,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )).toThrow('Plaintext size must be 256 bits or smaller')
        })

        test('works correctly with exactly 256 bits', () => {
            const exactly256Bits = (2n ** 256n) - 1n
            expect(() => prepareIT256(
                exactly256Bits,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )).not.toThrow()
        })

        test('works correctly with exactly 129 bits (boundary)', () => {
            const exactly129Bits = 2n ** 128n // 129 bits
            expect(() => prepareIT256(
                exactly129Bits,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )).not.toThrow()
        })
    })

    describe('decryptUint error cases', () => {
        test('produces incorrect result when user key has wrong length', () => {
            const { ciphertext } = prepareIT(
                12345n,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            const wrongKey = '1234567890123456789012345678901' // 31 chars
            // Function doesn't throw, but produces incorrect decryption
            const decrypted = decryptUint(ciphertext, wrongKey)
            expect(decrypted).not.toBe(12345n)
        })

        test('produces incorrect result when user key has invalid hex', () => {
            const { ciphertext } = prepareIT(
                12345n,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            const invalidKey = '1234567890123456789012345678901g' // invalid hex
            // Function may throw if NaN is used in encryption, or produce incorrect result
            try {
                const decrypted = decryptUint(ciphertext, invalidKey)
                expect(decrypted).not.toBe(12345n)
            } catch (e) {
                // If it throws, that's also acceptable behavior
                expect(e).toBeDefined()
            }
        })
    })

    describe('decryptUint256 error cases', () => {
        test('produces incorrect result when user key has wrong length', () => {
            const { ciphertext } = prepareIT256(
                2n ** 200n,
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            const wrongKey = '1234567890123456789012345678901' // 31 chars
            // Function doesn't throw, but produces incorrect decryption
            const decrypted = decryptUint256(ciphertext, wrongKey)
            expect(decrypted).not.toBe(2n ** 200n)
        })

        test('produces incorrect result when ciphertext structure is invalid', () => {
            const invalidCiphertext = { ciphertextHigh: 0n, ciphertextLow: 0n }
            // Function doesn't throw but will produce wrong result
            const decrypted = decryptUint256(invalidCiphertext, VALID_USER_KEY)
            // With zero ciphertext, it will decrypt to some value (not necessarily zero)
            expect(typeof decrypted).toBe('bigint')
            // The important thing is that it doesn't throw and produces a result
        })
    })

    describe('decryptString error cases', () => {
        test('produces incorrect result when user key has wrong length', () => {
            const { ciphertext } = buildStringInputText(
                'Hello',
                createTestSender(),
                TEST_CONSTANTS.CONTRACT_ADDRESS,
                TEST_CONSTANTS.FUNCTION_SELECTOR
            )
            const wrongKey = '1234567890123456789012345678901' // 31 chars
            // Function doesn't throw, but produces incorrect decryption
            const decrypted = decryptString(ciphertext, wrongKey)
            expect(decrypted).not.toBe('Hello')
        })

        test('handles empty ciphertext array', () => {
            const emptyCiphertext = { value: [] }
            const result = decryptString(emptyCiphertext, VALID_USER_KEY)
            expect(result).toBe('')
        })
    })

    describe('RSA function error cases', () => {
        test('decryptRSA throws error with invalid private key format', () => {
            const invalidPrivateKey = new Uint8Array([1, 2, 3]) // Too short, invalid format
            const validCiphertext = 'ba1a97832d6d14082c114e0f52139aab470a4749226bfab0d3ef37158049aa20fb53dae26c2df056130bcaee2821bdeb750a8369c2c348d6f4772f007dc43cdc9e79557332a62f521458c85fd19afc1eb31dffea3d03fa6e1eaf65fff08e2e04efb74798943bd8d2c3f6bcf0cdbeedf84316d14586ec796d1bea81c5c96454a0658a5869f51674625bca102617c861e6bff74f58799c88262c3138cff78cd8927516c9d5ebc544f3e07c0d14bdc34f3606f6e61b2498bc2ec38864032d39b3d865ecaad2d7c74e31508e1a3dd25a0e1dc5a5f697ed0f46ccea31f3c5a4ee722ddc95a9d3400ce0ea3c6c4b8986a5bb8cf76aa636072ecfbdff9762baf05d13c1'
            expect(() => decryptRSA(invalidPrivateKey, validCiphertext)).toThrow()
        })

        test('decryptRSA throws error with invalid ciphertext format', () => {
            // Use a valid RSA private key from the unit tests
            const RSA_PRIVATE_KEY = new Uint8Array([
                48,130,4,165,2,1,0,2,130,1,1,
                0,203,212,1,219,233,54,219,255,86,215,
                27,83,167,202,239,99,211,200,121,104,193,
                198,153,37,45,134,123,166,216,57,23,77,
                80,199,137,111,178,32,81,81,93,25,3,
                118,157,61,101,125,233,112,80,132,62,91,
                245,158,176,207,167,230,194,0,254,203,162,
                62,33,182,162,235,115,162,218,149,177,215,
                247,155,44,9,142,27,204,64,106,30,63,
                244,146,228,190,94,169,1,203,164,5,42,
                140,110,141,117,74,145,171,66,163,227,33,
                44,21,16,83,104,16,149,111,93,122,236,
                210,220,135,210,172,116,209,173,52,86,196,
                185,253,185,138,200,240,145,245,102,131,150,
                129,207,188,50,60,94,138,164,172,70,227,
                58,192,32,152,113,187,164,250,75,146,173,
                170,46,161,172,109,128,182,87,81,11,231,
                162,177,248,62,236,125,38,54,24,228,100,
                253,112,116,13,105,64,73,84,158,252,61,
                193,62,60,55,120,249,73,3,193,57,225,
                173,75,244,59,41,202,141,202,64,77,188,
                100,204,230,241,75,150,233,23,184,80,111,
                246,40,3,6,102,228,142,28,153,87,18,
                185,50,11,23,209,94,245,163,54,188,32,
                62,124,140,43,2,3,1,0,1,2,130,
                1,0,123,243,107,69,254,102,188,22,101,
                10,222,181,90,190,144,33,150,242,188,210,
                53,180,190,0,219,212,130,113,141,223,250,
                9,172,108,11,105,255,90,163,216,228,210,
                135,70,164,140,103,161,208,73,218,204,240,
                215,31,96,231,137,0,67,214,10,160,231,
                216,188,11,232,114,222,216,45,90,219,217,
                144,202,36,116,253,66,140,41,3,171,4,
                198,67,198,232,143,212,36,214,208,173,231,
                238,94,4,4,198,37,24,188,155,3,234,
                229,139,87,43,220,108,214,88,233,166,97,
                80,143,82,72,206,150,205,91,139,239,161,
                239,200,105,58,16,165,140,249,63,244,226,
                36,92,210,112,66,252,65,253,77,34,239,
                219,72,81,112,80,142,47,143,254,169,26,
                208,14,241,127,70,32,212,118,68,100,118,
                232,217,67,182,45,204,221,203,169,237,201,
                35,29,187,190,160,197,238,246,115,221,131,
                235,117,190,231,139,248,4,34,193,32,199,
                199,160,254,144,157,109,243,193,104,24,251,
                190,27,96,184,17,19,218,191,103,172,227,
                168,220,244,34,217,157,1,104,234,136,11,
                179,161,93,46,36,122,237,159,162,215,19,
                167,134,47,64,65,2,129,129,0,252,158,
                104,19,125,107,47,189,75,101,61,175,53,
                59,47,42,148,244,112,130,26,245,174,164,
                118,159,26,235,195,44,71,122,157,101,68,
                194,205,106,197,27,151,107,198,19,42,167,
                139,244,219,240,66,9,90,80,198,173,98,
                254,238,205,6,125,166,1,230,28,79,48,
                199,104,223,55,80,173,20,28,123,149,164,
                116,76,60,51,229,153,207,153,62,237,251,
                243,138,137,41,169,2,114,98,51,163,212,
                137,80,40,71,122,70,207,0,237,188,174,
                93,175,159,96,5,236,196,73,35,225,97,
                184,98,29,84,49,2,129,129,0,206,142,
                107,170,138,158,123,134,95,190,180,40,22,
                155,39,32,168,5,183,96,122,188,204,181,
                6,111,127,176,124,5,78,248,250,94,168,
                76,249,195,108,99,157,82,8,3,190,105,
                236,220,83,74,190,80,240,232,69,66,142,
                58,22,235,74,137,161,143,147,211,200,244,
                135,12,93,218,200,169,20,87,192,234,255,
                29,178,160,12,211,28,135,208,12,18,18,
                188,229,213,151,253,56,202,42,169,15,59,
                223,167,225,139,46,48,149,251,124,161,127,
                97,124,186,44,244,66,220,117,137,17,24,
                45,22,91,155,27,2,129,129,0,153,102,
                196,2,153,213,158,14,208,26,241,131,84,
                202,212,208,129,213,146,0,159,200,115,61,
                241,190,154,69,114,166,143,221,88,120,231,
                113,119,246,15,45,187,28,186,18,103,131,
                136,204,175,70,77,131,138,113,164,196,35,
                106,117,174,208,243,57,252,203,52,131,174,
                54,89,107,187,22,101,147,225,219,246,58,
                0,89,78,241,160,202,111,51,58,240,159,
                95,251,207,97,25,253,159,98,28,195,174,
                203,151,126,110,49,69,144,108,154,241,73,
                221,32,73,162,176,214,95,55,158,239,61,
                61,15,111,137,241,2,129,129,0,205,107,
                244,133,153,240,125,86,168,247,198,193,171,
                161,199,235,1,79,22,13,60,99,113,142,
                131,4,246,79,117,55,238,79,76,232,64,
                166,181,42,118,44,39,116,66,134,62,163,
                167,173,130,164,109,219,159,138,207,254,157,
                230,5,143,33,4,249,137,9,242,113,3,
                71,31,180,99,118,118,56,198,1,21,116,
                124,123,126,18,227,13,151,191,255,145,37,
                211,121,27,208,89,68,86,66,208,249,86,
                137,90,179,195,48,63,159,153,137,92,47,
                139,171,120,152,102,159,236,18,116,43,109,
                8,194,24,126,139,2,129,129,0,250,151,
                181,39,117,43,137,20,16,47,19,185,136,
                45,231,199,42,233,169,71,208,82,196,125,
                231,137,107,194,8,173,107,184,64,173,181,
                238,99,144,157,123,114,217,162,192,57,163,
                83,55,39,41,34,119,64,232,243,26,94,
                215,188,236,178,228,93,0,253,51,223,31,
                210,30,209,114,57,42,96,118,183,0,236,
                167,139,64,150,253,254,242,254,51,95,195,
                178,66,193,190,26,140,109,4,27,89,202,
                190,77,181,27,173,213,80,129,240,115,78,
                143,188,233,162,20,22,227,26,254,131,238,
                62,55,151,170,151
            ])
            const invalidCiphertext = 'invalid' // Not valid hex or wrong format
            expect(() => decryptRSA(RSA_PRIVATE_KEY, invalidCiphertext)).toThrow()
        })

        test('recoverUserKey throws error with invalid private key', () => {
            const invalidPrivateKey = new Uint8Array([1, 2, 3])
            const validShare = 'ba1a97832d6d14082c114e0f52139aab470a4749226bfab0d3ef37158049aa20fb53dae26c2df056130bcaee2821bdeb750a8369c2c348d6f4772f007dc43cdc9e79557332a62f521458c85fd19afc1eb31dffea3d03fa6e1eaf65fff08e2e04efb74798943bd8d2c3f6bcf0cdbeedf84316d14586ec796d1bea81c5c96454a0658a5869f51674625bca102617c861e6bff74f58799c88262c3138cff78cd8927516c9d5ebc544f3e07c0d14bdc34f3606f6e61b2498bc2ec38864032d39b3d865ecaad2d7c74e31508e1a3dd25a0e1dc5a5f697ed0f46ccea31f3c5a4ee722ddc95a9d3400ce0ea3c6c4b8986a5bb8cf76aa636072ecfbdff9762baf05d13c1'
            expect(() => recoverUserKey(invalidPrivateKey, validShare, validShare)).toThrow()
        })
    })
})

