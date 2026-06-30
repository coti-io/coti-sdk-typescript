import forge from 'node-forge'
import { BaseWallet, getBytes, SigningKey, solidityPacked, solidityPackedKeccak256, hexlify, Wallet } from "ethers"
import { BuildItUint256WithSignerParams, CtUint256Like, ctString, ctUint, ctUint256, itString, itUint, itUint256, itUint256Signed, SerializableCtUint, SerializableCtUint256 } from './types';
import { bigintToBytesBE, bytesToBigint, bytesToHex, ciphertextBytesToCtUint256, CT_SIZE, ctUint256ToBytes, ctUintToBytes } from './bytes';

const BLOCK_SIZE = 16 // AES block size in bytes
const HEX_BASE = 16
const EIGHT_BYTES = 8
const MAX_PLAINTEXT_BIT_SIZE = 256

function assertUintInRange(plaintext: bigint, maxBits: number, errorMessage: string): bigint {
    const value = BigInt(plaintext)
    if (value < 0n || value >= 1n << BigInt(maxBits)) {
        throw new RangeError(errorMessage)
    }
    return value
}

function assertAesKeySize(key: Uint8Array): void {
    if (key.length !== BLOCK_SIZE) {
        throw new RangeError("Key size must be 128 bits.")
    }
}

function splitCtBlock(block: Uint8Array): { cipher: Uint8Array; r: Uint8Array } {
    return {
        cipher: block.subarray(0, BLOCK_SIZE),
        r: block.subarray(BLOCK_SIZE)
    }
}

function packEncryptBlocks(...blocks: Array<{ ciphertext: Uint8Array; r: Uint8Array }>): Uint8Array {
    return new Uint8Array(blocks.flatMap(({ ciphertext, r }) => [...ciphertext, ...r]))
}

export function encrypt(key: Uint8Array, plaintext: Uint8Array): { ciphertext: Uint8Array; r: Uint8Array } {
    // Ensure plaintext is smaller than 128 bits (16 bytes)
    if (plaintext.length > BLOCK_SIZE) {
        throw new RangeError("Plaintext size must be 128 bits or smaller.")
    }

    // Generate a random value 'r' of the same length as the block size
    const r = forge.random.getBytesSync(BLOCK_SIZE)

    // Get the encrypted random value 'r'
    const encryptedR = encryptNumber(r, key)

    // Pad the plaintext with zeros if it's smaller than the block size
    const plaintextPadded = new Uint8Array([...new Uint8Array(BLOCK_SIZE - plaintext.length), ...plaintext])

    // XOR the encrypted random value 'r' with the plaintext to obtain the ciphertext
    const ciphertext = new Uint8Array(BLOCK_SIZE)

    for (let i = 0; i < BLOCK_SIZE; i++) {
        ciphertext[i] = encryptedR[i] ^ plaintextPadded[i]
    }

    return {
        ciphertext,
        r: encodeString(r)
    }
}

// Helper function to validate input sizes
function validateDecryptInputs(key: Uint8Array, r: Uint8Array, ciphertext: Uint8Array): void {
    if (ciphertext.length !== BLOCK_SIZE) {
        throw new RangeError("Ciphertext size must be 128 bits.")
    }

    assertAesKeySize(key)

    if (r.length !== BLOCK_SIZE) {
        throw new RangeError("Random size must be 128 bits.")
    }
}

// Helper function to validate second block parameters
function validateSecondBlock(r2: Uint8Array | null, ciphertext2: Uint8Array | null): void {
    if (r2 !== null && r2.length !== BLOCK_SIZE) {
        throw new RangeError("Random2 size must be 128 bits, received " + r2.length + " bytes.")
    }

    if (ciphertext2 !== null && ciphertext2.length !== BLOCK_SIZE) {
        throw new RangeError("Ciphertext2 size must be 128 bits, received " + ciphertext2.length + " bytes.")
    }

    if (r2 !== null && ciphertext2 === null) {
        throw new RangeError("Ciphertext2 is required.")
    }

    if (ciphertext2 !== null && r2 === null) {
        throw new RangeError("Random2 is required.")
    }
}

// Helper function to decrypt a single block
function decryptBlock(key: Uint8Array, r: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    const encryptedR = encryptNumber(r, key)
    const plaintext = new Uint8Array(BLOCK_SIZE)

    for (let i = 0; i < BLOCK_SIZE; i++) {
        plaintext[i] = encryptedR[i] ^ ciphertext[i]
    }

    return plaintext
}

// Refactored decrypt function with reduced complexity
export function decrypt(key: Uint8Array, r: Uint8Array, ciphertext: Uint8Array, r2: Uint8Array | null = null, ciphertext2: Uint8Array | null = null): Uint8Array {
    validateDecryptInputs(key, r, ciphertext)
    validateSecondBlock(r2, ciphertext2)

    const plaintext = decryptBlock(key, r, ciphertext)

    // Handle second block if provided
    if (r2 !== null && ciphertext2 !== null) {
        const plaintext2 = decryptBlock(key, r2, ciphertext2)
        return new Uint8Array([...plaintext, ...plaintext2])
    }

    return plaintext
}

export function generateRSAKeyPair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
    // Generate a new RSA key pair
    const rsaKeyPair = forge.pki.rsa.generateKeyPair({ bits: 2048 })

    // Convert keys to DER format
    const privateKey = forge.asn1.toDer(forge.pki.privateKeyToAsn1(rsaKeyPair.privateKey)).data
    const publicKey = forge.asn1.toDer(forge.pki.publicKeyToAsn1(rsaKeyPair.publicKey)).data

    return {
        privateKey: encodeString(privateKey),
        publicKey: encodeString(publicKey)
    }
}

export function decryptRSA(privateKey: Uint8Array, ciphertext: string): string {
    // Convert privateKey from Uint8Array to PEM format
    const privateKeyPEM = forge.pki.privateKeyToPem(forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(forge.util.createBuffer(bytesToBinaryString(privateKey)))));

    // Decrypt using RSA-OAEP
    const rsaPrivateKey = forge.pki.privateKeyFromPem(privateKeyPEM);

    const decrypted = rsaPrivateKey.decrypt(forge.util.hexToBytes(ciphertext), 'RSA-OAEP', {
        md: forge.md.sha256.create()
    });

    const decryptedBytes = encodeString(decrypted)

    return bytesToHex(decryptedBytes)
}

export function recoverUserKey(privateKey: Uint8Array, encryptedKeyShare0: string, encryptedKeyShare1: string): string {
    const decryptedKeyShare0: string = decryptRSA(privateKey, encryptedKeyShare0);
    const decryptedKeyShare1: string = decryptRSA(privateKey, encryptedKeyShare1);


    const bufferKeyShare0 = encodeKey(decryptedKeyShare0)
    const bufferKeyShare1 = encodeKey(decryptedKeyShare1)
    const aesKeyBytes = new Uint8Array(BLOCK_SIZE)

    for (let i = 0; i < BLOCK_SIZE; i++) {
        aesKeyBytes[i] = bufferKeyShare0[i] ^ bufferKeyShare1[i];
    }
    return bytesToHex(aesKeyBytes)
}


export function sign(message: string, privateKey: string) {
    const key = new SigningKey(privateKey)
    const sig = key.sign(message)
    return signatureToBytes(sig)
}

// Computes the COTI IT message hash shared by signInputText and buildItSignature.
function buildItMessageHash(
    signerAddress: string,
    contractAddress: string,
    functionSelector: string,
    ct: bigint
): string {
    return solidityPackedKeccak256(
        ["address", "address", "bytes4", "uint256"],
        [signerAddress, contractAddress, functionSelector, ct]
    )
}

function signatureToBytes(signature: ReturnType<SigningKey['sign']>): Uint8Array {
    return new Uint8Array([...getBytes(signature.r), ...getBytes(signature.s), ...getBytes(`0x0${signature.v - 27}`)])
}

function signItUintDigest(
    signerAddress: string,
    contractAddress: string,
    functionSelector: string,
    ct: bigint,
    privateKey: string
): Uint8Array {
    return sign(buildItMessageHash(signerAddress, contractAddress, functionSelector, ct), privateKey)
}

export function signInputText(
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string,
    ct: bigint
) {
    return signItUintDigest(sender.wallet.address, contractAddress, functionSelector, ct, sender.wallet.privateKey)
}

function buildUintInputText(
    plaintext: bigint,
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string,
    maxBits: 64 | 128,
    errorMessage: string
): itUint {
    const plaintextBigInt = assertUintInRange(plaintext, maxBits, errorMessage)

    const ctInt = encryptUint128Unchecked(plaintextBigInt, sender.userKey)
    const signature = signInputText(sender, contractAddress, functionSelector, ctInt)

    return {
        ciphertext: ctInt,
        signature
    }
}

/**
 * @deprecated Use `prepareIT` for unsigned integer input-text values. This
 * legacy helper is limited to 64-bit plaintexts and will be removed in a
 * future major version.
 */
export function buildInputText(
    plaintext: bigint,
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string
): itUint {
    return buildUintInputText(
        plaintext,
        sender,
        contractAddress,
        functionSelector,
        64,
        "Plaintext size must be 64 bits or smaller."
    )
}

export function buildStringInputText(
    plaintext: string,
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string
): itString {
    let encoder = new TextEncoder()

    // Encode the plaintext string into bytes (UTF-8 encoded)        
    let encodedStr = encoder.encode(plaintext)

    const inputText = {
        ciphertext: { value: new Array<bigint>() },
        signature: new Array<Uint8Array | string>()
    }

    // Process the encoded string in chunks of 8 bytes
    // We use 8 bytes since we will use ctUint64 to store
    // each chunk of 8 characters
    for (let startIdx = 0; startIdx < encodedStr.length; startIdx += EIGHT_BYTES) {
        const endIdx = Math.min(startIdx + EIGHT_BYTES, encodedStr.length)

        const byteArr = new Uint8Array([...encodedStr.slice(startIdx, endIdx), ...new Uint8Array(EIGHT_BYTES - (endIdx - startIdx))]) // pad the end of the string with zeros if needed

        const it = buildUintInputText(
            decodeUint(byteArr), // convert the 8-byte hex string into a number
            sender,
            contractAddress,
            functionSelector,
            64,
            "Plaintext size must be 64 bits or smaller."
        )

        inputText.ciphertext.value.push(it.ciphertext)
        inputText.signature.push(it.signature)
    }

    return inputText
}

/**
 * Decrypts a 64-bit ctUint ciphertext using the user's AES key.
 *
 * - A zero ciphertext is short-circuited to `0n` without validating the key,
 *   since it represents uninitialized/empty on-chain storage. This allows DApps
 *   to read empty balances before the user has configured their AES key.
 *   Note: this means `decryptUint(0n, invalidKey)` returns `0n` without throwing.
 * - For non-zero ciphertexts, key validation is performed by `encodeKey`
 *   (strips "0x", lowercases, enforces 128-bit hex). Invalid keys throw
 *   rather than producing garbage.
 *
 * @param ciphertext - The encrypted 64-bit value (bigint).
 * @param userKey - The AES key (32 hex chars, optionally "0x"-prefixed).
 * @returns The decrypted plaintext as a bigint.
 * @throws Error if the key is invalid (null, wrong length, non-hex) and ciphertext is non-zero.
 */
export function decryptUint(ciphertext: ctUint, userKey: string): bigint {
    // A zero ciphertext represents uninitialized/empty storage, which decrypts
    // to plaintext 0. Short-circuit before touching the key so callers can read
    // empty values without a valid key (and to avoid returning AES garbage).
    if (ciphertext === 0n) {
        return 0n
    }

    const { cipher, r } = splitCtBlock(ctUintToBytes(ciphertext))

    // encodeKey validates and normalizes the key (strips "0x", enforces 128-bit)
    const userKeyBytes = encodeKey(userKey)

    // Decrypt the cipher
    const decryptedMessage = decrypt(userKeyBytes, r, cipher)

    return decodeUint(decryptedMessage)
}

/**
 * Decrypts a 256-bit ciphertext (ctUint256) using the user's AES key.
 * @param {ctUint256} ciphertext - The 256-bit ciphertext object with ciphertextHigh and ciphertextLow.
 * @param {string} userKey - The user's AES key as a hex string (32 characters).
 * @returns {bigint} - The decrypted plaintext as a BigInt.
 */
export function decryptUint256(ciphertext: ctUint256, userKey: string): bigint {
    const ciphertextBytes = ctUint256ToBytes(ciphertext)
    const { cipher: cipherHigh, r: rHigh } = splitCtBlock(ciphertextBytes.slice(0, CT_SIZE))
    const { cipher: cipherLow, r: rLow } = splitCtBlock(ciphertextBytes.slice(CT_SIZE))

    const userKeyBytes = encodeKey(userKey)

    // Decrypt both parts using the decrypt function
    const decryptedMessage = decrypt(userKeyBytes, rHigh, cipherHigh, rLow, cipherLow)

    return decodeUint(decryptedMessage)
}

export function decryptString(ciphertext: ctString, userKey: string): string {
    const allBytes: number[] = []

    for (let i = 0; i < ciphertext.value.length; i++) {
        const decrypted = decryptUint(BigInt(ciphertext.value[i]), userKey)
        const chunkBytes = encodeUint(decrypted)

        // encodeUint returns 16 bytes (BLOCK_SIZE). 
        // buildStringInputText uses 8-byte chunks (EIGHT_BYTES).
        // The relevant 8 bytes are at the end since encodeUint is Big-Endian.
        for (let j = BLOCK_SIZE - EIGHT_BYTES; j < BLOCK_SIZE; j++) {
            allBytes.push(chunkBytes[j])
        }
    }

    // Trim trailing zero bytes (padding added by buildStringInputText)
    let end = allBytes.length
    while (end > 0 && allBytes[end - 1] === 0) {
        end--
    }

    const decoder = new TextDecoder()
    return decoder.decode(new Uint8Array(allBytes.slice(0, end)))
}

export function generateRandomAesKeySizeNumber(): string {
    return forge.random.getBytesSync(BLOCK_SIZE)
}

export function encodeString(str: string): Uint8Array {
    // Use iterable directly without converting to array first
    return new Uint8Array(Array.from(str, (char) => Number.parseInt(char.codePointAt(0)?.toString(HEX_BASE)!, HEX_BASE)))
}

function bytesToBinaryString(bytes: Uint8Array): string {
    return Array.from(bytes, byte => String.fromCodePoint(byte)).join('')
}

function toForgeBinaryString(value: string | Uint8Array): string {
    return typeof value === 'string' ? value : bytesToBinaryString(value)
}

export function encodeKey(userKey: string): Uint8Array {
    // Validate and normalize the key (strips "0x", lowercases, enforces 128-bit)
    // so that every encrypt/decrypt path rejects malformed keys consistently
    // instead of silently producing NaN/garbage bytes.
    const normalizedKey = normalizeAesKey(userKey)
    const keyBytes = new Uint8Array(16)

    for (let i = 0; i < 32; i += 2) {
        keyBytes[i / 2] = Number.parseInt(normalizedKey.slice(i, i + 2), HEX_BASE)
    }

    return keyBytes
}

export function encodeUint(plaintext: bigint): Uint8Array {
    return bigintToBytesBE(plaintext, BLOCK_SIZE)
}

export function decodeUint(plaintextBytes: Uint8Array): bigint {
    return bytesToBigint(plaintextBytes)
}

export function encryptNumber(r: string | Uint8Array, key: Uint8Array) {
    assertAesKeySize(key)

    // Create a new AES cipher using the provided key
    const cipher = forge.cipher.createCipher('AES-ECB', forge.util.createBuffer(bytesToBinaryString(key)))

    // Encrypt the random value 'r' using AES in ECB mode
    cipher.start()
    cipher.update(forge.util.createBuffer(toForgeBinaryString(r)))
    cipher.finish()

    // Get the encrypted random value 'r' and ensure it's exactly 16 bytes
    const encryptedR = encodeString(cipher.output.data).slice(0, BLOCK_SIZE)

    return encryptedR
}

function signIT(sender: Uint8Array, contract: Uint8Array, hashFunc: Uint8Array, ct: Uint8Array, signingKey: Uint8Array): Uint8Array {
    const key = new SigningKey(signingKey)
    const message = solidityPackedKeccak256(["bytes", "bytes", "bytes4", "bytes"], [sender, contract, hashFunc, ct])
    const sig = key.sign(message)
    return signatureToBytes(sig)
}

export function prepareIT(
    plaintext: bigint,
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string
): itUint {
    return buildUintInputText(
        plaintext,
        sender,
        contractAddress,
        functionSelector,
        128,
        "Plaintext size must be 128 bits or smaller. To prepare a 256 bit plaintext, use prepareIT256 instead."
    )
}

// Helper function to create ciphertext for 128-bit plaintext
function createCiphertext128(plaintextBigInt: bigint, userAesKey: Uint8Array): Uint8Array {
    const plaintextBytes = bigintToBytesBE(plaintextBigInt, BLOCK_SIZE)
    const encrypted = encrypt(userAesKey, plaintextBytes)
    const encryptedHigh = encrypt(userAesKey, new Uint8Array(BLOCK_SIZE))
    return packEncryptBlocks(encryptedHigh, encrypted)
}

// Helper function to create ciphertext for 256-bit plaintext
function createCiphertext256(plaintextBigInt: bigint, userAesKey: Uint8Array): Uint8Array {
    const plaintextBytes = bigintToBytesBE(plaintextBigInt, CT_SIZE)
    const high = encrypt(userAesKey, plaintextBytes.slice(0, BLOCK_SIZE))
    const low = encrypt(userAesKey, plaintextBytes.slice(BLOCK_SIZE))
    return packEncryptBlocks(high, low)
}

function encryptUint128Unchecked(plaintext: bigint, userKey: string): ctUint {
    const encrypted = encrypt(encodeKey(userKey), encodeUint(plaintext))
    return decodeUint(packEncryptBlocks(encrypted))
}

function encryptUint256ToBytes(plaintextBigInt: bigint, userAesKey: Uint8Array): Uint8Array {
    const bitSize = plaintextBigInt.toString(2).length
    return bitSize <= MAX_PLAINTEXT_BIT_SIZE / 2
        ? createCiphertext128(plaintextBigInt, userAesKey)
        : createCiphertext256(plaintextBigInt, userAesKey)
}

/**
 * Encrypts an unsigned 64-bit value into a ctUint ciphertext without building an IT signature.
 */
export function encryptUint(plaintext: bigint, userKey: string): ctUint {
    return encryptUint128Unchecked(
        assertUintInRange(plaintext, 64, "Plaintext size must be 64 bits or smaller."),
        userKey
    )
}

/**
 * Encrypts an unsigned 256-bit value into a ctUint256 ciphertext without building an IT signature.
 */
export function encryptUint256(plaintext: bigint, userKey: string): ctUint256 {
    const plaintextBigInt = assertUintInRange(
        plaintext,
        MAX_PLAINTEXT_BIT_SIZE,
        "Plaintext size must be 256 bits or smaller."
    )
    return ciphertextBytesToCtUint256(encryptUint256ToBytes(plaintextBigInt, encodeKey(userKey)))
}

function toBigInt(value: unknown): bigint {
    if (value === undefined || value === null) {
        throw new Error("Missing bigint value.")
    }
    if (typeof value === 'bigint') {
        return value
    }
    if (typeof value === 'number' || typeof value === 'string') {
        return BigInt(value)
    }
    throw new Error("Invalid bigint value.")
}

export function normalizeCtPayload(value: SerializableCtUint, type: 'ctUint64'): ctUint;
export function normalizeCtPayload(value: SerializableCtUint256, type: 'ctUint256'): ctUint256;
export function normalizeCtPayload(value: SerializableCtUint | SerializableCtUint256, type: 'ctUint64' | 'ctUint256'): ctUint | ctUint256;
export function normalizeCtPayload(
    value: SerializableCtUint | SerializableCtUint256,
    type: 'ctUint64' | 'ctUint256'
): ctUint | ctUint256 {
    if (type === 'ctUint64') {
        return toBigInt(value as SerializableCtUint)
    }

    if (!value || typeof value !== 'object') {
        throw new Error("Invalid ctUint256 payload.")
    }

    if ('ciphertextHigh' in value && 'ciphertextLow' in value) {
        return {
            ciphertextHigh: toBigInt(value.ciphertextHigh),
            ciphertextLow: toBigInt(value.ciphertextLow)
        }
    }

    throw new Error("Invalid ctUint256 payload.")
}

function isZeroValue(value: unknown): boolean {
    try {
        return toBigInt(value) === 0n
    } catch {
        return false
    }
}

function asRecord(value: unknown): Record<string, unknown> & Record<number, unknown> | null {
    return value && typeof value === 'object'
        ? value as Record<string, unknown> & Record<number, unknown>
        : null
}

type ParsedCtUint256 =
    | { kind: 'nested'; parts: [unknown, unknown, unknown, unknown] }
    | { kind: 'flat'; high: unknown; low: unknown }

function parseCtUint256Shape(value: unknown): ParsedCtUint256 | null {
    const record = asRecord(value)
    if (!record) {
        return null
    }

    const highObj = asRecord(record.high)
    const lowObj = asRecord(record.low)
    if (
        highObj?.high !== undefined &&
        highObj?.low !== undefined &&
        lowObj?.high !== undefined &&
        lowObj?.low !== undefined
    ) {
        return {
            kind: 'nested',
            parts: [highObj.high, highObj.low, lowObj.high, lowObj.low]
        }
    }

    const high = record.ciphertextHigh ?? record[0]
    const low = record.ciphertextLow ?? record[1]
    if (high !== undefined && low !== undefined) {
        return { kind: 'flat', high, low }
    }

    return null
}

export function isCtUint256Shape(value: unknown): value is CtUint256Like {
    return parseCtUint256Shape(value) !== null
}

export function isZeroCtUint256(ciphertext: unknown): boolean {
    if (isZeroValue(ciphertext)) {
        return true
    }

    const parsed = parseCtUint256Shape(ciphertext)
    if (!parsed) {
        return false
    }

    if (parsed.kind === 'nested') {
        return parsed.parts.every(isZeroValue)
    }

    return isZeroValue(parsed.high) && isZeroValue(parsed.low)
}

export function decryptCtUint256(ciphertext: unknown, userKey: string): bigint {
    const parsed = parseCtUint256Shape(ciphertext)
    if (!parsed) {
        throw new Error("Invalid ctUint256 payload.")
    }

    if (parsed.kind === 'nested') {
        const [highHigh, highLow, lowHigh, lowLow] = parsed.parts
        const d1 = decryptUint(toBigInt(highHigh), userKey)
        const d2 = decryptUint(toBigInt(highLow), userKey)
        const d3 = decryptUint(toBigInt(lowHigh), userKey)
        const d4 = decryptUint(toBigInt(lowLow), userKey)
        return (d1 << 192n) + (d2 << 128n) + (d3 << 64n) + d4
    }

    return decryptUint256(
        {
            ciphertextHigh: toBigInt(parsed.high),
            ciphertextLow: toBigInt(parsed.low)
        },
        userKey
    )
}

export async function buildItUint256WithSigner({
    value,
    aesKey,
    signerAddress,
    contractAddress,
    functionSelector,
    signMessage
}: BuildItUint256WithSignerParams): Promise<itUint256Signed> {
    const plaintextBigInt = assertUintInRange(
        value,
        MAX_PLAINTEXT_BIT_SIZE,
        "Plaintext size must be 256 bits or smaller."
    )

    const ciphertext = encryptUint256(plaintextBigInt, aesKey)
    // Browser wallets sign the flat ABI payload. This intentionally differs
    // from prepareIT256, which signs the raw 64-byte ciphertext for the
    // private-key path used by legacy helpers.
    const message = solidityPacked(
        ["address", "address", "bytes4", "uint256", "uint256"],
        [
            signerAddress,
            contractAddress,
            functionSelector,
            ciphertext.ciphertextHigh,
            ciphertext.ciphertextLow
        ]
    )
    const signature = await signMessage(getBytes(message))

    return { ciphertext, signature }
}

/**
 * Prepares a 256-bit IT by encrypting both parts of the plaintext, signing the encrypted message,
 * and packaging the resulting data for smart contract submission.
 */
export function prepareIT256(
    plaintext: bigint,
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string,
): itUint256 {
    const plaintextBigInt = assertUintInRange(
        plaintext,
        MAX_PLAINTEXT_BIT_SIZE,
        "Plaintext size must be 256 bits or smaller."
    )

    const senderBytes = getBytes(sender.wallet.address)
    const contractBytes = getBytes(contractAddress)
    const hashFuncBytes = getBytes(functionSelector)
    const signingKeyBytes = getBytes(sender.wallet.privateKey)

    const ct = encryptUint256ToBytes(plaintextBigInt, encodeKey(sender.userKey))

    const signature = signIT(senderBytes, contractBytes, hashFuncBytes, ct, signingKeyBytes)

    return {
        ciphertext: ciphertextBytesToCtUint256(ct),
        signature
    }
}
// ------------- Wallet Plugin Additions -------------

/**
 * Validates and normalizes an AES key: ensures it is present, strips the "0x"
 * prefix, and lowercases it. COTI uses a 128-bit AES key, so only 32-character
 * hex strings are accepted.
 *
 * @param aesKey - The AES key, optionally prefixed with "0x".
 * @returns The normalized lowercase hex string.
 * @throws Error if the key is empty/null/undefined, contains non-hex characters, or is not 32 hex characters.
 */
export function normalizeAesKey(aesKey: string | null | undefined): string {
    if (!aesKey) {
        throw new Error("AES key is required")
    }

    const trimmed = aesKey.startsWith("0x") ? aesKey.slice(2) : aesKey
    const lowered = trimmed.toLowerCase()

    if (!/^[0-9a-f]+$/.test(lowered)) {
        throw new Error("Invalid AES key: contains non-hexadecimal characters")
    }

    if (lowered.length !== 32) {
        throw new Error(`Invalid AES key: expected 32 hex characters (128-bit), got ${lowered.length}`)
    }

    return lowered
}

/**
 * Builds a COTI input-text (IT) signature over (signer, contract, selector, ciphertext).
 *
 * @deprecated Use `signInputText` with an ethers `Wallet` for private-key
 * signing. For browser signers, use `buildItUint256WithSigner` for 256-bit
 * values. This private-key convenience wrapper will be removed in a future
 * major version.
 *
 * @param signerAddress - Address of the signer; must match the address derived from privateKey.
 * @param contractAddress - Target contract address.
 * @param functionSelector - 4-byte function selector (e.g. "0x11223344").
 * @param ciphertext - The encrypted value being signed.
 * @param privateKey - Signer's private key.
 * @returns The 65-byte signature as a hex string.
 * @throws Error if signerAddress does not match the address derived from privateKey.
 */
export function buildItSignature(
    signerAddress: string,
    contractAddress: string,
    functionSelector: string,
    ciphertext: bigint,
    privateKey: string
): string {
    const wallet = new Wallet(privateKey);
    if ( wallet.address.toLowerCase() !== signerAddress.toLowerCase()) {
        throw new Error("Invalid signer: signerAddress does not match the address derived from privateKey");
    }
    return hexlify(signItUintDigest(signerAddress, contractAddress, functionSelector, ciphertext, privateKey));
}
