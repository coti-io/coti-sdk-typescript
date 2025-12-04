import forge from 'node-forge'
import {BaseWallet, getBytes, SigningKey, solidityPackedKeccak256} from "ethers"
import { ctString, ctUint, ctUint256, itString, itUint, itUint256 } from './types';

const BLOCK_SIZE = 16 // AES block size in bytes
const HEX_BASE = 16
const EIGHT_BYTES = 8
const MAX_PLAINTEXT_BIT_SIZE = 256
const CT_SIZE = 32

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

    if (key.length !== BLOCK_SIZE) {
        throw new RangeError("Key size must be 128 bits.")
    }

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
    const rsaKeyPair = forge.pki.rsa.generateKeyPair({bits: 2048})

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
    const privateKeyPEM = forge.pki.privateKeyToPem(forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(forge.util.createBuffer(privateKey))));

    // Decrypt using RSA-OAEP
    const rsaPrivateKey = forge.pki.privateKeyFromPem(privateKeyPEM);

    const decrypted = rsaPrivateKey.decrypt(forge.util.hexToBytes(ciphertext), 'RSA-OAEP', {
        md: forge.md.sha256.create()
    });

    const decryptedBytes = encodeString(decrypted)

    const userKey: Array<string> = []

    for (let i = 0; i < decryptedBytes.length; i++) {
        userKey.push(
            decryptedBytes[i]
                .toString(16)
                .padStart(2, '0') // make sure each cell is one byte
        )
    }

    return userKey.join("")
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
    const aesKey: Array<string> = []

    let byte = ''

    for (let i = 0; i < aesKeyBytes.length; i++) {
        byte = aesKeyBytes[i].toString(HEX_BASE).padStart(2, '0') // ensure that the zero byte is represented using two digits

        aesKey.push(byte)
    }

    return aesKey.join("")
}


export function sign(message: string, privateKey: string) {
    const key = new SigningKey(privateKey)
    const sig = key.sign(message)
    return new Uint8Array([...getBytes(sig.r), ...getBytes(sig.s), ...getBytes(`0x0${sig.v - 27}`)])
}

export function signInputText(
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string,
    ct: bigint
) {
    const message = solidityPackedKeccak256(
        ["address", "address", "bytes4", "uint256"],
        [sender.wallet.address, contractAddress, functionSelector, ct]
    )

    return sign(message, sender.wallet.privateKey);
}

export function buildInputText(
    plaintext: bigint,
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string
): itUint {
    if (plaintext >= BigInt(2) ** BigInt(64)) {
        throw new RangeError("Plaintext size must be 64 bits or smaller.")
    }

    // Convert the plaintext to bytes
    const plaintextBytes = encodeUint(plaintext)

    // Convert user key to bytes
    const keyBytes = encodeKey(sender.userKey)

    // Encrypt the plaintext using AES key
    const {ciphertext, r} = encrypt(keyBytes, plaintextBytes)
    const ct = new Uint8Array([...ciphertext, ...r])

    // Convert the ciphertext to BigInt
    const ctInt = decodeUint(ct)

    const signature = signInputText(sender, contractAddress, functionSelector, ctInt);

    return {
        ciphertext: ctInt,
        signature: signature
    }
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

        const it = buildInputText(
            decodeUint(byteArr), // convert the 8-byte hex string into a number
            sender,
            contractAddress,
            functionSelector
        )

        inputText.ciphertext.value.push(it.ciphertext)
        inputText.signature.push(it.signature)
    }

    return inputText
}

export function decryptUint(ciphertext: ctUint, userKey: string): bigint {
    // Convert ciphertext to Uint8Array
    let ctArray = new Uint8Array()

    while (ciphertext > 0) {
        const temp = new Uint8Array([Number(ciphertext & BigInt(255))])
        ctArray = new Uint8Array([...temp, ...ctArray])
        ciphertext >>= BigInt(8)
    }

    ctArray = new Uint8Array([...new Uint8Array(32 - ctArray.length), ...ctArray])

    // Split CT into two 128-bit arrays r and cipher
    const cipher = ctArray.subarray(0, BLOCK_SIZE)
    const r = ctArray.subarray(BLOCK_SIZE)

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

    // Convert ciphertextHigh to Uint8Array
    let ctHighArray = new Uint8Array()
    let ctHigh = ciphertext.ciphertextHigh

    while (ctHigh > 0) {
        const temp = new Uint8Array([Number(ctHigh & BigInt(255))])
        ctHighArray = new Uint8Array([...temp, ...ctHighArray])
        ctHigh >>= BigInt(8)
    }

    ctHighArray = new Uint8Array([...new Uint8Array(CT_SIZE - ctHighArray.length), ...ctHighArray])

    // Convert ciphertextLow to Uint8Array
    let ctLowArray = new Uint8Array()
    let ctLow = ciphertext.ciphertextLow

    while (ctLow > 0) {
        const temp = new Uint8Array([Number(ctLow & BigInt(255))])
        ctLowArray = new Uint8Array([...temp, ...ctLowArray])
        ctLow >>= BigInt(8)
    }

    ctLowArray = new Uint8Array([...new Uint8Array(CT_SIZE - ctLowArray.length), ...ctLowArray])

    // Split high part into cipher and r
    const cipherHigh = ctHighArray.subarray(0, BLOCK_SIZE)
    const rHigh = ctHighArray.subarray(BLOCK_SIZE)

    // Split low part into cipher and r
    const cipherLow = ctLowArray.subarray(0, BLOCK_SIZE)
    const rLow = ctLowArray.subarray(BLOCK_SIZE)

    const userKeyBytes = encodeKey(userKey)

    // Decrypt both parts using the decrypt function
    const decryptedMessage = decrypt(userKeyBytes, rHigh, cipherHigh, rLow, cipherLow)

    return decodeUint(decryptedMessage)
}

export function decryptString(ciphertext: ctString, userKey: string): string {
    let encodedStr = new Uint8Array()

    for (let i = 0; i < ciphertext.value.length; i++) {
        const decrypted = decryptUint(BigInt(ciphertext.value[i]), userKey)
        
        encodedStr = new Uint8Array([...encodedStr, ...encodeUint(decrypted)])
    }

    const decoder = new TextDecoder()

    // Use replaceAll instead of replace with regex
    return decoder
        .decode(encodedStr)
        .replaceAll('\0', '')
}

export function generateRandomAesKeySizeNumber(): string {
    return forge.random.getBytesSync(BLOCK_SIZE)
}

export function encodeString(str: string): Uint8Array {
    // Use iterable directly without converting to array first
    return new Uint8Array(Array.from(str, (char) => Number.parseInt(char.codePointAt(0)?.toString(HEX_BASE)!, HEX_BASE)))
}

export function encodeKey(userKey: string): Uint8Array {
    const keyBytes = new Uint8Array(16)

    for (let i = 0; i < 32; i += 2) {
        keyBytes[i / 2] = Number.parseInt(userKey.slice(i, i + 2), HEX_BASE)
    }

    return keyBytes
}

export function encodeUint(plaintext: bigint): Uint8Array {
    // Convert the plaintext to bytes in little-endian format

    const plaintextBytes = new Uint8Array(BLOCK_SIZE) // Allocate a buffer of size 16 bytes

    for (let i = 15; i >= 0; i--) {
        plaintextBytes[i] = Number(plaintext & BigInt(255))
        plaintext >>= BigInt(8)
    }

    return plaintextBytes
}

export function decodeUint(plaintextBytes: Uint8Array): bigint {
    const plaintext: Array<string> = []

    let byte = ''

    for (let i = 0; i < plaintextBytes.length; i++) {
        byte = plaintextBytes[i].toString(HEX_BASE).padStart(2, '0') // ensure that the zero byte is represented using two digits

        plaintext.push(byte)
    }

    return BigInt("0x" + plaintext.join(""))
}

export function encryptNumber(r: string | Uint8Array, key: Uint8Array) {
    // Ensure key size is 128 bits (16 bytes)
    if (key.length != BLOCK_SIZE) {
        throw new RangeError("Key size must be 128 bits.")
    }

    // Create a new AES cipher using the provided key
    const cipher = forge.cipher.createCipher('AES-ECB', forge.util.createBuffer(key))

    // Encrypt the random value 'r' using AES in ECB mode
    cipher.start()
    cipher.update(forge.util.createBuffer(r))
    cipher.finish()

    // Get the encrypted random value 'r' and ensure it's exactly 16 bytes
    const encryptedR = encodeString(cipher.output.data).slice(0, BLOCK_SIZE)

    return encryptedR
}

// ---------- Helper Functions for IT Preparation ----------
function writeBigUInt128BE(buf: Uint8Array, value: bigint) {
    for (let i = 15; i >= 0; i--) {
        buf[i] = Number(value & BigInt(0xff))
        value >>= BigInt(8)
    }
}

function writeBigUInt256BE(buf: Uint8Array, value: bigint) {
    for (let i = 31; i >= 0; i--) {
        buf[i] = Number(value & BigInt(0xff))
        value >>= BigInt(8)
    }
}

function signIT(sender: Uint8Array, contract: Uint8Array, hashFunc: Uint8Array, ct: Uint8Array, signingKey: Uint8Array): Uint8Array {
    const key = new SigningKey(signingKey)
    const message = solidityPackedKeccak256(["bytes", "bytes", "bytes4", "bytes"], [sender, contract, hashFunc, ct])
    const sig = key.sign(message)
    return new Uint8Array([...getBytes(sig.r), ...getBytes(sig.s), ...getBytes(`0x0${sig.v - 27}`)])
}

export function prepareIT(
    plaintext: bigint,
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string
): itUint {
    const plaintextBigInt = BigInt(plaintext)
    const bitSize = plaintextBigInt.toString(2).length
    
    if (bitSize > MAX_PLAINTEXT_BIT_SIZE / 2) { 
        throw new RangeError("Plaintext size must be 128 bits or smaller. To prepare a 256 bit plaintext, use prepareIT256 instead.")
    }

    // Convert the plaintext to bytes
    const plaintextBytes = encodeUint(plaintext)

    // Convert user key to bytes
    const keyBytes = encodeKey(sender.userKey)

    // Encrypt the plaintext using AES key
    const {ciphertext, r} = encrypt(keyBytes, plaintextBytes)
    const ct = new Uint8Array([...ciphertext, ...r])

    // Convert the ciphertext to BigInt
    const ctInt = decodeUint(ct)

    const signature = signInputText(sender, contractAddress, functionSelector, ctInt);

    return {
        ciphertext: ctInt,
        signature: signature
    }
}

// Helper function to create ciphertext for 128-bit plaintext
function createCiphertext128(plaintextBigInt: bigint, userAesKey: Uint8Array): Uint8Array {
    const plaintextBytes = new Uint8Array(BLOCK_SIZE)
    writeBigUInt128BE(plaintextBytes, plaintextBigInt)
    const { ciphertext, r } = encrypt(userAesKey, plaintextBytes)

    const zero = BigInt(0)
    const zeroBytes = new Uint8Array(BLOCK_SIZE)
    writeBigUInt128BE(zeroBytes, zero)
    const { ciphertext: ciphertextHigh, r: rHigh } = encrypt(userAesKey, zeroBytes)

    return new Uint8Array([...ciphertextHigh, ...rHigh, ...ciphertext, ...r])
}

// Helper function to create ciphertext for 256-bit plaintext
function createCiphertext256(plaintextBigInt: bigint, userAesKey: Uint8Array): Uint8Array {
    const plaintextBytes = new Uint8Array(CT_SIZE)
    writeBigUInt256BE(plaintextBytes, plaintextBigInt)
    const high = encrypt(userAesKey, plaintextBytes.slice(0, BLOCK_SIZE))
    const low = encrypt(userAesKey, plaintextBytes.slice(BLOCK_SIZE))
    return new Uint8Array([...high.ciphertext, ...high.r, ...low.ciphertext, ...low.r])
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
    const plaintextBigInt = BigInt(plaintext)
    const bitSize = plaintextBigInt.toString(2).length
    if (bitSize > MAX_PLAINTEXT_BIT_SIZE) {
        throw new RangeError("Plaintext size must be 256 bits or smaller.")
    }

    const userAesKey = encodeKey(sender.userKey)
    const senderBytes = getBytes(sender.wallet.address)
    const contractBytes = getBytes(contractAddress)
    const hashFuncBytes = getBytes(functionSelector)
    const signingKeyBytes = getBytes(sender.wallet.privateKey)

    // Choose appropriate encryption based on bit size
    const ct = bitSize <= MAX_PLAINTEXT_BIT_SIZE / 2
        ? createCiphertext128(plaintextBigInt, userAesKey)
        : createCiphertext256(plaintextBigInt, userAesKey)

    const signature = signIT(senderBytes, contractBytes, hashFuncBytes, ct, signingKeyBytes)
    const ciphertextHigh = ct.slice(0, CT_SIZE)
    const ciphertextLow = ct.slice(CT_SIZE)

    // Convert Uint8Array to hex string
    const ciphertextHighHex = Array.from(ciphertextHigh)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('')
    const ciphertextLowHex = Array.from(ciphertextLow)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('')

    const ciphertextHighUint = BigInt('0x' + ciphertextHighHex)
    const ciphertextLowUint = BigInt('0x' + ciphertextLowHex)

    return { 
        ciphertext: { 
            ciphertextHigh: ciphertextHighUint, 
            ciphertextLow: ciphertextLowUint 
        }, 
        signature 
    }
}