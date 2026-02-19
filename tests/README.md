# Test Report

**Generated:** 2026-02-19T06:39:44.430Z

---

## Coverage Summary

| File | Statements | Branches | Functions | Lines |
| ---- | ---------- | -------- | --------- | ----- |
| **All files** | 100% | 100% | 100% | 100% |
| crypto_utils.ts | 100% | 100% | 100% | 100% |
| index.ts | 100% | 100% | 100% | 100% |


## Test Results Summary

| Metric       | Value |
| ------------ | ----- |
| Total Tests  | 337 |
| Passed       | 337 |
| Failed       | 0 |
| Errors       | 0 |
| Duration     | 14.18s |

---

## Test Suites

### tests/unit/error.handling.test.ts

- **Tests:** 29
- **Failures:** 0
- **Errors:** 0
- **Time:** 4.212s

- ✅ throws RangeError when plaintext exceeds 16 bytes
- ✅ throws RangeError when key length is not 16 bytes
- ✅ throws RangeError when ciphertext length is not 16 bytes
- ✅ throws RangeError when key length is not 16 bytes
- ✅ throws RangeError when random length is not 16 bytes
- ✅ throws RangeError when r2 is provided but ciphertext2 is null
- ✅ throws RangeError when ciphertext2 is provided but r2 is null
- ✅ throws RangeError when r2 length is not 16 bytes
- ✅ throws RangeError when ciphertext2 length is not 16 bytes
- ✅ throws RangeError when key length is not 16 bytes
- ✅ produces incorrect result when user key length is not 32 hex characters
- ✅ produces incorrect result when user key has invalid hex characters
- ✅ produces zero-filled array when user key is empty
- ✅ throws RangeError when plaintext exceeds 128 bits
- ✅ works correctly with exactly 128 bits
- ✅ throws RangeError when plaintext exceeds 256 bits
- ✅ works correctly with exactly 256 bits
- ✅ works correctly with exactly 129 bits (boundary)
- ✅ throws RangeError when plaintext exceeds 64 bits
- ✅ works correctly with exactly 64 bits
- ✅ produces incorrect result when user key has wrong length
- ✅ produces incorrect result when user key has invalid hex
- ✅ produces incorrect result when user key has wrong length
- ✅ produces incorrect result when ciphertext structure is invalid
- ✅ produces incorrect result when user key has wrong length
- ✅ handles empty ciphertext array
- ✅ decryptRSA throws error with invalid private key format
- ✅ decryptRSA throws error with invalid ciphertext format
- ✅ recoverUserKey throws error with invalid private key

---

### tests/integration/validation.test.ts

- **Tests:** 37
- **Failures:** 0
- **Errors:** 0
- **Time:** 0.699s

- ✅ prepareIT produces incorrect result with user key that is too short
- ✅ prepareIT produces incorrect result with user key that is too long
- ✅ prepareIT produces incorrect result with user key containing invalid hex
- ✅ decryptUint produces incorrect result with invalid user key
- ✅ decryptUint256 produces incorrect result with invalid user key
- ✅ decryptString produces incorrect result with invalid user key
- ✅ prepareIT throws error with contract address that is too short
- ✅ prepareIT handles contract address without 0x prefix
- ✅ prepareIT throws error with contract address containing invalid hex
- ✅ prepareIT256 throws error with invalid contract address
- ✅ buildStringInputText throws error with invalid contract address
- ✅ prepareIT throws error with function selector that is too short
- ✅ prepareIT throws error with function selector that is too long
- ✅ prepareIT throws error with function selector without 0x prefix
- ✅ prepareIT throws error with function selector containing invalid hex
- ✅ prepareIT256 throws error with invalid function selector
- ✅ buildStringInputText throws error with invalid function selector
- ✅ Wallet creation throws error with invalid private key
- ✅ Wallet creation handles private key without 0x prefix
- ✅ prepareIT throws error when sender has invalid wallet
- ✅ decryptUint produces incorrect result when given prepareIT256 ciphertext format
- ✅ decryptUint256 produces incorrect result when given prepareIT ciphertext format
- ✅ decryptString throws error when given prepareIT ciphertext format
- ✅ decryptUint produces incorrect result when given buildStringInputText ciphertext format
- ✅ prepareIT throws error when sender is missing wallet property
- ✅ prepareIT throws error when sender is missing userKey property
- ✅ prepareIT256 throws error when sender structure is invalid
- ✅ buildStringInputText throws error when sender structure is invalid
- ✅ prepareIT works with exactly 128 bits (boundary)
- ✅ prepareIT throws with 129 bits (should use prepareIT256)
- ✅ prepareIT256 works with exactly 256 bits (boundary)
- ✅ prepareIT256 works with exactly 129 bits (boundary between prepareIT and prepareIT256)
- ✅ prepareIT256 throws with 257 bits
- ✅ buildStringInputText handles very long strings
- ✅ buildStringInputText handles strings with only null bytes
- ✅ buildStringInputText handles strings with only special characters
- ✅ buildStringInputText handles basic unicode characters

---

### tests/integration/cross.function.test.ts

- **Tests:** 14
- **Failures:** 0
- **Errors:** 0
- **Time:** 0.324s

- ✅ prepareIT output can be decrypted by decryptUint
- ✅ buildInputText output can be decrypted by decryptUint
- ✅ prepareIT and buildInputText produce compatible formats
- ✅ prepareIT256 output can be decrypted by decryptUint256
- ✅ prepareIT256 works with values <= 128 bits
- ✅ prepareIT256 works with values > 128 bits
- ✅ buildStringInputText output can be decrypted by decryptString
- ✅ buildStringInputText handles strings of various lengths
- ✅ can process uint, uint256, and string in same session
- ✅ same user key works across all data types
- ✅ same data with different contract addresses produces different signatures
- ✅ same data with different function selectors produces different signatures
- ✅ wrong user key fails to decrypt
- ✅ ciphertext from prepareIT has different format than decryptUint256 expects

---

### tests/integration/e2e.flow.test.ts

- **Tests:** 15
- **Failures:** 0
- **Errors:** 0
- **Time:** 0.321s

- ✅ complete flow: encrypt and decrypt small value
- ✅ complete flow: encrypt and decrypt large value
- ✅ complete flow: encrypt and decrypt zero
- ✅ different plaintexts produce different ciphertexts
- ✅ complete flow: encrypt and decrypt 128-bit value
- ✅ complete flow: encrypt and decrypt 256-bit value
- ✅ complete flow: encrypt and decrypt value > 128 bits
- ✅ different plaintexts produce different ciphertexts
- ✅ complete flow: encrypt and decrypt short string
- ✅ complete flow: encrypt and decrypt long string
- ✅ complete flow: encrypt and decrypt empty string
- ✅ complete flow: encrypt and decrypt string with special characters
- ✅ different strings produce different ciphertexts
- ✅ sequence: prepareIT → prepareIT256 → buildStringInputText
- ✅ sequence: multiple prepareIT operations with different values

---

### tests/integration/format.compatibility.test.ts

- **Tests:** 15
- **Failures:** 0
- **Errors:** 0
- **Time:** 0.288s

- ✅ output matches itUint type structure
- ✅ ciphertext is valid BigInt for contract submission
- ✅ signature can be converted to bytes format for contracts
- ✅ output matches itUint256 type structure
- ✅ ciphertextHigh and ciphertextLow are valid BigInts
- ✅ format is compatible with contract struct parameters
- ✅ output matches itString type structure
- ✅ ciphertext.value is array of BigInts for contract submission
- ✅ signature array matches ciphertext array length
- ✅ format is compatible with contract array parameters
- ✅ contract address format is valid
- ✅ function selector format is valid (4 bytes)
- ✅ ciphertext can be converted to hex string
- ✅ signature can be converted to hex string
- ✅ ciphertextHigh and ciphertextLow can be converted to hex strings

---

### tests/integration/signature.tampering.test.ts

- **Tests:** 12
- **Failures:** 0
- **Errors:** 0
- **Time:** 0.288s

- ✅ signature verifies with original parameters
- ✅ signature fails verification when contractAddress is tampered
- ✅ signature fails verification when functionSelector is tampered
- ✅ signature fails verification when ciphertext is tampered
- ✅ signature fails verification when sender address is tampered
- ✅ signInputText produces valid signature for given parameters
- ✅ signInputText result is invalid when any parameter is changed
- ✅ prepareIT256 signatures differ when contractAddress changes
- ✅ prepareIT256 signatures differ when functionSelector changes
- ✅ string signatures differ when contractAddress changes
- ✅ string signatures differ when functionSelector changes
- ✅ string signatures differ when plaintext changes

---

### tests/integration/signature.verification.test.ts

- **Tests:** 12
- **Failures:** 0
- **Errors:** 0
- **Time:** 0.298s

- ✅ signature has correct format (65 bytes: r + s + v)
- ✅ signature changes when plaintext changes
- ✅ signature changes when contract address changes
- ✅ signature changes when function selector changes
- ✅ signature format is consistent (same structure)
- ✅ signature has correct format (65 bytes)
- ✅ signature changes when plaintext changes
- ✅ signature format is consistent (same structure)
- ✅ signatures array has correct format (one per chunk)
- ✅ signature count matches ciphertext chunk count
- ✅ signatures change when string changes
- ✅ signature format is consistent (same structure)

---

### tests/unit/crypto_utils.test.ts

- **Tests:** 116
- **Failures:** 0
- **Errors:** 0
- **Time:** 6.522s

- ✅ encodeString - basic encoding of a string as a Uint8Array
- ✅ encodeString - asserts limitation with multi-byte characters (overflow)
- ✅ encodeKey - basic encoding of an AES key as a Uint8Array
- ✅ encodeUint - basic encoding of a Uint as a Uint8Array in little-endian format
- ✅ decodeUint - basic decoding of a Uint8Array in little-endian format to a Uint
- ✅ AES encryption of a number provided in string format
- ✅ AES encryption of a number provided in Uint8Array format
- ✅ throws RangeError when the key length is not 16 bytes
- ✅ decrypt - decrypt an unsigned integer
- ✅ decryptRSA - decrypt an RSA key
- ✅ sign - recover correct address from signature
- ✅ sign - sign an arbitrary digest
- ✅ signInputText - recover correct address from signature
- ✅ signInputText - sign arbitrary input text
- ✅ encrypt the message "123"
- ✅ throw RangeError when the plaintext length is more than 16 bytes
- ✅ decrypt the encrypted version of the message "123"
- ✅ throw RangeError when the ciphertext length is not 16 bytes
- ✅ throw RangeError when the random number length is not 16 bytes
- ✅ decrypt - decrypt with second block (r2 and ciphertext2)
- ✅ decrypt - throws error when r2 is provided but ciphertext2 is null
- ✅ decrypt - throws error when ciphertext2 is provided but r2 is null
- ✅ build input text from an arbitrary unsigned integer
- ✅ build input text with 80-bit value (larger than 70 bits)
- ✅ build input text with 100-bit value
- ✅ build input text with 120-bit value
- ✅ build input text with 127-bit value (near 128-bit limit)
- ✅ build input text with exactly 128-bit value
- ✅ throw RangeError when the value of plaintext is greater than 128 bits
- ✅ encrypt and decrypt round-trip with 100-bit value
- ✅ encrypt and decrypt round-trip with 128-bit value
- ✅ decrypt the ciphertext of an arbitrary unsigned integer
- ✅ decryptUint with 8-bit value
- ✅ decryptUint with 16-bit value
- ✅ decryptUint with 32-bit value
- ✅ decryptUint with 64-bit value
- ✅ decryptUint with 128-bit value
- ✅ decryptUint with zero value
- ✅ decryptUint with large value
- ✅ build input text from an arbitrary string
- ✅ buildStringInputText with short string (less than 8 bytes)
- ✅ buildStringInputText with exactly 8 bytes
- ✅ buildStringInputText with 9 bytes (2 chunks)
- ✅ buildStringInputText with long string (multiple chunks)
- ✅ buildStringInputText with empty string
- ✅ buildStringInputText with special characters
- ✅ buildStringInputText with unicode characters (basic)
- ✅ buildStringInputText with numbers and letters
- ✅ buildStringInputText with newlines and tabs
- ✅ buildStringInputText produces different ciphertexts for different strings
- ✅ buildStringInputText produces different signatures for different contract addresses
- ✅ buildStringInputText produces different signatures for different function selectors
- ✅ buildStringInputText with return structure
- ✅ buildStringInputText with round-trip encryption and decryption
- ✅ buildStringInputText with exactly 16 bytes (2 full chunks)
- ✅ buildStringInputText with exactly 24 bytes (3 full chunks)
- ✅ buildStringInputText with emojis (multi-byte)
- ✅ buildStringInputText with Hebrew (multi-byte + RTL)
- ✅ buildStringInputText with Arabic (multi-byte + RTL)
- ✅ buildStringInputText with Chinese (multi-byte)
- ✅ buildStringInputText with boundary: 7 bytes (1 chunk)
- ✅ buildStringInputText with boundary: 8 bytes (1 chunk)
- ✅ buildStringInputText with boundary: 9 bytes (2 chunks)
- ✅ buildStringInputText with boundary: 15 bytes (2 chunks)
- ✅ buildStringInputText with boundary: 16 bytes (2 chunks)
- ✅ buildStringInputText with boundary: 17 bytes (3 chunks)
- ✅ decrypt the ciphertext of an arbitrary string
- ✅ decryptString round-trip with short string (less than 8 bytes)
- ✅ decryptString round-trip with exactly 8 bytes
- ✅ decryptString round-trip with long string (multiple chunks)
- ✅ decryptString round-trip with empty string
- ✅ decryptString round-trip with special characters
- ✅ decryptString round-trip with unicode characters (basic)
- ✅ decryptString round-trip with numbers and letters
- ✅ decryptString round-trip with newlines and tabs
- ✅ decryptString round-trip with round-trip: emojis
- ✅ decryptString round-trip with round-trip: Hebrew
- ✅ decryptString round-trip with round-trip: Japanese
- ✅ decryptString round-trip with round-trip: 4-byte UTF-8
- ✅ decryptString round-trip with round-trip: 7 bytes
- ✅ decryptString round-trip with round-trip: 8 bytes
- ✅ decryptString round-trip with round-trip: 9 bytes
- ✅ decryptString round-trip with round-trip: 15 bytes
- ✅ decryptString round-trip with round-trip: 16 bytes
- ✅ decryptString round-trip with round-trip: 17 bytes
- ✅ prepareIT256 with value <= 128 bits (should pad high part with zeros)
- ✅ prepareIT256 with 129-bit value (just above 128 bits)
- ✅ prepareIT256 with 200-bit value
- ✅ prepareIT256 with 255-bit value (near 256-bit limit)
- ✅ prepareIT256 with exactly 256-bit value
- ✅ throw RangeError when plaintext exceeds 256 bits
- ✅ encrypt and decrypt round-trip with 100-bit value (<= 128 bits)
- ✅ encrypt and decrypt round-trip with 129-bit value (> 128 bits)
- ✅ encrypt and decrypt round-trip with 200-bit value
- ✅ encrypt and decrypt round-trip with 256-bit value
- ✅ prepareIT256 produces different ciphertexts for different values
- ✅ prepareIT256 produces different signatures for different contract addresses
- ✅ decryptUint256 with value <= 128 bits (padded high part)
- ✅ decryptUint256 with 129-bit value
- ✅ decryptUint256 with 150-bit value
- ✅ decryptUint256 with 200-bit value
- ✅ decryptUint256 with 255-bit value
- ✅ decryptUint256 with exactly 256-bit value
- ✅ decryptUint256 with zero value
- ✅ decryptUint256 with small value (1)
- ✅ decryptUint256 with large random value
- ✅ decryptUint256 verifies ciphertext structure
- ✅ generateRSAKeyPair - generates valid RSA key pair
- ✅ generateRSAKeyPair - generates different key pairs on each call
- ✅ generateRSAKeyPair - validates key properties
- ✅ generateRSAKeyPair - generated keys can be used for RSA operations
- ✅ recoverUserKey - recovers AES key from two encrypted key shares
- ✅ recoverUserKey - produces consistent results with same inputs
- ✅ generateRandomAesKeySizeNumber - generates 16-byte random value
- ✅ generateRandomAesKeySizeNumber - generates different values on each call
- ✅ generateRandomAesKeySizeNumber - can be used as AES key material

---

### tests/integration/mock.parity.test.ts

- **Tests:** 5
- **Failures:** 0
- **Errors:** 0
- **Time:** 0.32s

- ✅ encrypt produces different ciphertexts on each call (real randomness)
- ✅ decrypt is agnostic to randomness source
- ✅ prepareIT with real randomness produces different ciphertexts but same decrypted value
- ✅ prepareIT round-trip works for boundary values with real randomness
- ✅ prepareIT256 with real randomness produces different ciphertexts but same decrypted value

---

### tests/unit/property.roundtrip.test.ts

- **Tests:** 73
- **Failures:** 0
- **Errors:** 0
- **Time:** 0.351s

- ✅ round-trip #0: decodeUint(encodeUint(x)) === x
- ✅ round-trip #1: decodeUint(encodeUint(x)) === x
- ✅ round-trip #2: decodeUint(encodeUint(x)) === x
- ✅ round-trip #3: decodeUint(encodeUint(x)) === x
- ✅ round-trip #4: decodeUint(encodeUint(x)) === x
- ✅ round-trip #5: decodeUint(encodeUint(x)) === x
- ✅ round-trip #6: decodeUint(encodeUint(x)) === x
- ✅ round-trip #7: decodeUint(encodeUint(x)) === x
- ✅ round-trip #8: decodeUint(encodeUint(x)) === x
- ✅ round-trip #9: decodeUint(encodeUint(x)) === x
- ✅ round-trip #10: decodeUint(encodeUint(x)) === x
- ✅ round-trip #11: decodeUint(encodeUint(x)) === x
- ✅ round-trip #12: decodeUint(encodeUint(x)) === x
- ✅ round-trip #13: decodeUint(encodeUint(x)) === x
- ✅ round-trip #14: decodeUint(encodeUint(x)) === x
- ✅ round-trip #15: decodeUint(encodeUint(x)) === x
- ✅ round-trip #16: decodeUint(encodeUint(x)) === x
- ✅ round-trip #17: decodeUint(encodeUint(x)) === x
- ✅ round-trip #18: decodeUint(encodeUint(x)) === x
- ✅ round-trip #19: decodeUint(encodeUint(x)) === x
- ✅ round-trip #20: decodeUint(encodeUint(x)) === x
- ✅ round-trip #21: decodeUint(encodeUint(x)) === x
- ✅ round-trip #22: decodeUint(encodeUint(x)) === x
- ✅ round-trip #23: decodeUint(encodeUint(x)) === x
- ✅ round-trip #24: decodeUint(encodeUint(x)) === x
- ✅ round-trip #25: decodeUint(encodeUint(x)) === x
- ✅ round-trip #26: decodeUint(encodeUint(x)) === x
- ✅ round-trip #27: decodeUint(encodeUint(x)) === x
- ✅ round-trip #28: decodeUint(encodeUint(x)) === x
- ✅ round-trip #29: decodeUint(encodeUint(x)) === x
- ✅ round-trip #30: decodeUint(encodeUint(x)) === x
- ✅ round-trip #31: decodeUint(encodeUint(x)) === x
- ✅ round-trip #32: decodeUint(encodeUint(x)) === x
- ✅ round-trip #33: decodeUint(encodeUint(x)) === x
- ✅ round-trip #34: decodeUint(encodeUint(x)) === x
- ✅ round-trip #35: decodeUint(encodeUint(x)) === x
- ✅ round-trip #36: decodeUint(encodeUint(x)) === x
- ✅ round-trip #37: decodeUint(encodeUint(x)) === x
- ✅ round-trip #38: decodeUint(encodeUint(x)) === x
- ✅ round-trip #39: decodeUint(encodeUint(x)) === x
- ✅ round-trip #40: decodeUint(encodeUint(x)) === x
- ✅ round-trip #41: decodeUint(encodeUint(x)) === x
- ✅ round-trip #42: decodeUint(encodeUint(x)) === x
- ✅ round-trip #43: decodeUint(encodeUint(x)) === x
- ✅ round-trip #44: decodeUint(encodeUint(x)) === x
- ✅ round-trip #45: decodeUint(encodeUint(x)) === x
- ✅ round-trip #46: decodeUint(encodeUint(x)) === x
- ✅ round-trip #47: decodeUint(encodeUint(x)) === x
- ✅ round-trip #48: decodeUint(encodeUint(x)) === x
- ✅ round-trip #49: decodeUint(encodeUint(x)) === x
- ✅ round-trip with zero
- ✅ round-trip with max 128-bit value
- ✅ encodeUint always produces 16-byte output
- ✅ encodeKey is idempotent for the same input
- ✅ encodeKey produces different output for different keys
- ✅ encodeKey with all-zeros produces zero array
- ✅ encodeKey with all-ff produces 255 array
- ✅ encrypt then decrypt round-trip with generated AES key
- ✅ full-cycle round-trip #0: decryptUint(prepareIT(x)) === x
- ✅ full-cycle round-trip #1: decryptUint(prepareIT(x)) === x
- ✅ full-cycle round-trip #2: decryptUint(prepareIT(x)) === x
- ✅ full-cycle round-trip #3: decryptUint(prepareIT(x)) === x
- ✅ full-cycle round-trip #4: decryptUint(prepareIT(x)) === x
- ✅ full-cycle round-trip #5: decryptUint(prepareIT(x)) === x
- ✅ full-cycle round-trip #6: decryptUint(prepareIT(x)) === x
- ✅ full-cycle round-trip #7: decryptUint(prepareIT(x)) === x
- ✅ full-cycle round-trip #8: decryptUint(prepareIT(x)) === x
- ✅ full-cycle round-trip #9: decryptUint(prepareIT(x)) === x
- ✅ full-cycle round-trip #0: decryptUint256(prepareIT256(x)) === x
- ✅ full-cycle round-trip #1: decryptUint256(prepareIT256(x)) === x
- ✅ full-cycle round-trip #2: decryptUint256(prepareIT256(x)) === x
- ✅ full-cycle round-trip #3: decryptUint256(prepareIT256(x)) === x
- ✅ full-cycle round-trip #4: decryptUint256(prepareIT256(x)) === x

---

### tests/integration/bool.integration.test.ts

- **Tests:** 3
- **Failures:** 0
- **Errors:** 0
- **Time:** 0.253s

- ✅ round-trip: prepareIT and decryptUint with boolean TRUE (1n)
- ✅ round-trip: prepareIT and decryptUint with boolean FALSE (0n)
- ✅ utility: converting JS boolean to SDK-compatible bigint

---

### tests/unit/buildInputText.validation.test.ts

- **Tests:** 6
- **Failures:** 0
- **Errors:** 0
- **Time:** 0.305s

- ✅ throws RangeError when plaintext is exactly 2^64
- ✅ throws RangeError when plaintext exceeds 2^64
- ✅ throws RangeError when plaintext is 128-bit (far above 64-bit limit)
- ✅ succeeds with plaintext = 2^64 - 1 (maximum valid 64-bit value)
- ✅ succeeds with zero plaintext
- ✅ succeeds with small values within 64-bit range

---

