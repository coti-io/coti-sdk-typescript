import crypto from 'crypto'
import {
    BaseWallet,
    getBytes,
    SigningKey,
    solidityPackedKeccak256,
    keccak256,
    toUtf8Bytes
} from "ethers"
import {
    ctBool,
    ctString,
    ctUint8,
    ctUint16,
    ctUint32,
    ctUint64,
    ctUint128,
    ctUint256,
    ctInt8,
    ctInt16,
    ctInt32,
    ctInt64,
    ctInt128,
    ctInt256,
    itBool,
    itString,
    itUint8,
    itUint16,
    itUint32,
    itUint64,
    itUint128,
    itUint256,
    itInt8,
    itInt16,
    itInt32,
    itInt64,
    itInt128,
    itInt256
} from './types';

const BLOCK_SIZE = 16 // AES block size in bytes
const ADDRESS_SIZE = 20 // 160-bit is the output of the Keccak-256 algorithm on the sender/contract address
const FUNC_SIG_SIZE = 4
const CT_SIZE = 32
const KEY_SIZE = 32
const HEX_BASE = 16
const EIGHT_BYTES = 8
const MAX_PLAINTEXT_BIT_SIZE = 256

function validateBigIntRange(plaintext: unknown, min: bigint, max: bigint, typeName: string) {
    if (typeof plaintext !== "bigint") {
        throw new TypeError(`Plaintext for ${typeName} must be a BigInt value.`)
    }
    if ((plaintext as bigint) < min || (plaintext as bigint) > max) {
        throw new RangeError(`Plaintext for ${typeName} must be in [${min.toString()}, ${max.toString()}].`)
    }
}

export function encrypt(key: Uint8Array, plaintext: Uint8Array): { ciphertext: Uint8Array; r: Uint8Array } {
    // Ensure plaintext is smaller than 128 bits (16 bytes)
    if (plaintext.length > BLOCK_SIZE) {
        throw new RangeError("Plaintext size must be 128 bits or smaller.")
    }

    // Ensure key size is 128 bits (16 bytes)
    if (key.length !== BLOCK_SIZE) {
        throw new RangeError("Key size must be 128 bits.")
    }

    // Create a new AES cipher using the provided key
    const cipher = crypto.createCipheriv('aes-128-ecb', key, null)

    // Generate a random value 'r' of the same length as the block size
    const r = crypto.randomBytes(BLOCK_SIZE)

    // Encrypt the random value 'r' using AES in ECB mode
    const encryptedR = cipher.update(r)

    // Pad the plaintext with zeros if it's smaller than the block size
    const plaintextPadded = new Uint8Array([...new Uint8Array(BLOCK_SIZE - plaintext.length), ...plaintext])

    // XOR the encrypted random value 'r' with the plaintext to obtain the ciphertext
    const ciphertext = new Uint8Array(encryptedR.length)
    for (let i = 0; i < encryptedR.length; i++) {
        ciphertext[i] = encryptedR[i] ^ plaintextPadded[i]
    }

    return {
        ciphertext,
        r: new Uint8Array(r)
    }
}

export function decrypt(key: Uint8Array, r: Uint8Array, ciphertext: Uint8Array, r2?: Uint8Array, ciphertext2?: Uint8Array): Uint8Array {
    if (ciphertext.length !== BLOCK_SIZE) {
        throw new RangeError("Ciphertext size must be 128 bits.")
    }

    // Ensure key size is 128 bits (16 bytes)
    if (key.length !== BLOCK_SIZE) {
        throw new RangeError("Key size must be 128 bits, received " + key.length + " bytes.")
    }

    // Ensure random size is 128 bits (16 bytes)
    if (r.length !== BLOCK_SIZE) {
        throw new RangeError("Random size must be 128 bits, received " + r.length + " bytes.")
    }

    if (r2 !== undefined) {
        if (r2.length !== BLOCK_SIZE) {
            throw new RangeError("Random2 size must be 128 bits, received " + r2.length + " bytes.")
        }
        if (ciphertext2 === undefined) {
            throw new RangeError("Ciphertext2 is required.")
        }
    }

    if (ciphertext2 !== undefined) {
        if (ciphertext2.length !== BLOCK_SIZE) {
            throw new RangeError("Ciphertext2 size must be 128 bits, received " + ciphertext2.length + " bytes.")
        }
        if (r2 === undefined) {
            throw new RangeError("Random2 is required.")
        }
    }

    // Create a new AES cipher using the provided key
    const cipher = crypto.createCipheriv('aes-128-ecb', key, null)

    // Encrypt the random value 'r' using AES in ECB mode
    const encryptedR = cipher.update(r)

    // XOR the encrypted random value 'r' with the ciphertext to obtain the plaintext
    let plaintext = new Uint8Array(encryptedR.length)
    for (let i = 0; i < encryptedR.length; i++) {
        plaintext[i] = encryptedR[i] ^ ciphertext[i]
    }

    if (r2 !== undefined && ciphertext2 !== undefined) {
        // Encrypt the random value 'r2' using AES in ECB mode
        const encryptedR2 = cipher.update(r2)

        // XOR the encrypted random value 'r2' with the ciphertext2 to obtain the plaintext2
        const plaintext2 = new Uint8Array(encryptedR2.length)
        for (let i = 0; i < encryptedR2.length; i++) {
            plaintext2[i] = encryptedR2[i] ^ ciphertext2[i]
        }

        plaintext = new Uint8Array([...plaintext, ...plaintext2])
    }

    return plaintext
}

export function generateRSAKeyPair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
    // Generate a new RSA key pair
    const keyPair = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'der' // Specify 'der' format for binary data
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'der' // Specify 'der' format for binary data
        }
    })

    return {
        privateKey: new Uint8Array(keyPair.privateKey),
        publicKey: new Uint8Array(keyPair.publicKey)
    }
}

export function decryptRSA(privateKey: Uint8Array, ciphertext: string): string {
    // Load the private key in PEM format
    let privateKeyPEM = Buffer.from(privateKey).toString('base64')
    privateKeyPEM = `-----BEGIN PRIVATE KEY-----\n${privateKeyPEM}\n-----END PRIVATE KEY-----`

    // Decrypt the ciphertext using RSA-OAEP
    const decrypted = crypto.privateDecrypt({
        key: privateKeyPEM,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
    }, Buffer.from(ciphertext, 'hex'))

    const userKey: Array<string> = []

    for (let i = 0; i < decrypted.length; i++) {
        userKey.push(
            decrypted[i]
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


export function sign(message: Uint8Array, key: Uint8Array): Uint8Array {
    // Hash the concatenated message using Keccak-256
    const hash = keccak256(message)
    
    // Sign the message using ethers
    const signingKey = new SigningKey(key)
    const sig = signingKey.sign(hash)
    
    // Convert r, s, and v components to bytes
    const rBytes = getBytes(sig.r)
    const sBytes = getBytes(sig.s)
    const vByte = new Uint8Array([sig.v - 27]) // Convert v from 27-28 to 0-1

    // Concatenate r, s, and v bytes
    return new Uint8Array([...rBytes, ...sBytes, ...vByte])
}

export function signEIP191(message: Uint8Array, key: Uint8Array): Uint8Array {
    // For EIP-191, we need to hash the message with the personal message prefix
    // This is a simplified version - in practice you'd need to implement the full EIP-191 spec
    const personalMessage = `\x19Ethereum Signed Message:\n${message.length}${Buffer.from(message).toString('utf8')}`
    const hash = keccak256(toUtf8Bytes(personalMessage))
    
    // Sign the message using ethers
    const signingKey = new SigningKey(key)
    const sig = signingKey.sign(hash)
    
    // Convert r, s, and v components to bytes
    const rBytes = getBytes(sig.r)
    const sBytes = getBytes(sig.s)
    const vByte = new Uint8Array([sig.v])

    // Concatenate r, s, and v bytes
    return new Uint8Array([...rBytes, ...sBytes, ...vByte])
}


export function signInputText(
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string,
    ct: bigint
): Uint8Array {
    // Get the bytes of the sender, contract, and function signature
    const senderBytes = new Uint8Array(Buffer.from(sender.wallet.address.slice(2), 'hex'))
    const contractBytes = new Uint8Array(Buffer.from(contractAddress.slice(2), 'hex'))
    const funcSigBytes = new Uint8Array(Buffer.from(functionSelector.slice(2), 'hex'))
    
    // Convert ct to bytes (32 bytes for uint256)
    const ctBytes = new Uint8Array(32)
    for (let i = 31; i >= 0; i--) {
        ctBytes[i] = Number(ct & BigInt(255))
        ct >>= BigInt(8)
    }
    
    // Create the message to be signed by concatenating all inputs
    const message = new Uint8Array([...senderBytes, ...contractBytes, ...funcSigBytes, ...ctBytes])
    
    // Sign the message
    const key = new Uint8Array(Buffer.from(sender.wallet.privateKey.slice(2), 'hex'))
    return sign(message, key)
}


export function buildInputText(
    plaintext: bigint,
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string
): itUint8 | itUint16 | itUint32 | itUint64 {
    if (plaintext >= BigInt(2) ** BigInt(64)) {
        throw new RangeError("Plaintext size must be 64 bits or smaller.")
    }

    // Convert the plaintext to bytes using the new logic
    const plaintextBigInt = BigInt(plaintext)
    const bitSize = plaintextBigInt.toString(2).length
    if (bitSize > MAX_PLAINTEXT_BIT_SIZE / 2) {
        throw new RangeError("Plaintext size must be 128 bits or smaller. To prepare a 256 bit plaintext, use buildUint256InputText instead.")
    }

    const plaintextBytes = new Uint8Array(BLOCK_SIZE) // Allocate a buffer of size 16 bytes
    writeBigUInt128BE(plaintextBytes, plaintextBigInt) // Write the uint128 value to the buffer as big-endian
    
    // Convert user key to bytes
    const keyBytes = encodeKey(sender.userKey)

    // Encrypt the plaintext using AES key
    const {ciphertext, r} = encrypt(keyBytes, plaintextBytes)
    const ct = new Uint8Array([...ciphertext, ...r])

    // Convert the ciphertext to BigInt
    const ctInt = BigInt('0x' + Buffer.from(ct).toString('hex'))

    const signature = signInputText(sender, contractAddress, functionSelector, ctInt);

    return {
        ciphertext: ctInt,
        signature: signature
    }
}

export function buildUint8InputText(
    plaintext: bigint,
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string
): itUint8 {
    validateBigIntRange(plaintext, 0n, 255n, "uint8")
    return buildInputText(plaintext, sender, contractAddress, functionSelector)
}

export function buildUint16InputText(
    plaintext: bigint,
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string
): itUint16 {
    validateBigIntRange(plaintext, 0n, 65535n, "uint16")
    return buildInputText(plaintext, sender, contractAddress, functionSelector)
}

export function buildUint32InputText(
    plaintext: bigint,
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string
): itUint32 {
    validateBigIntRange(plaintext, 0n, 4294967295n, "uint32")
    return buildInputText(plaintext, sender, contractAddress, functionSelector)
}

export function buildUint64InputText(
    plaintext: bigint,
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string
): itUint64 {
    validateBigIntRange(plaintext, 0n, 18446744073709551615n, "uint64")
    return buildInputText(plaintext, sender, contractAddress, functionSelector)
}

export function buildUint128InputText(
    plaintext: bigint,
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string
): itUint128 {
    // Type and range validation for uint128
    validateBigIntRange(plaintext, 0n, (1n << 128n) - 1n, "uint128")
    
    // Convert the plaintext to bytes using the new logic
    const plaintextBigInt = BigInt(plaintext)
    const bitSize = plaintextBigInt.toString(2).length
    if (bitSize > MAX_PLAINTEXT_BIT_SIZE / 2) {
        throw new RangeError("Plaintext size must be 128 bits or smaller. To prepare a 256 bit plaintext, use buildUint256InputText instead.")
    }

    const plaintextBytes = new Uint8Array(BLOCK_SIZE) // Allocate a buffer of size 16 bytes
    writeBigUInt128BE(plaintextBytes, plaintextBigInt) // Write the uint128 value to the buffer as big-endian
    
    // Convert user key to bytes
    const keyBytes = encodeKey(sender.userKey)

    // Encrypt the plaintext using AES key
    const {ciphertext, r} = encrypt(keyBytes, plaintextBytes)
    const ct = new Uint8Array([...ciphertext, ...r])

    // Convert the ciphertext to BigInt
    const ctInt = BigInt('0x' + Buffer.from(ct).toString('hex'))

    const signature = signInputText(sender, contractAddress, functionSelector, ctInt);

    return {
        ciphertext: ctInt,
        signature: signature
    }
}

export function buildUint256InputText(
    plaintext: bigint,
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string
): itUint256 {
    // Type and range validation for uint256
    validateBigIntRange(plaintext, 0n, (1n << 256n) - 1n, "uint256")
    
    // Convert the plaintext to bytes
    const plaintextBigInt = BigInt(plaintext)
    const bitSize = plaintextBigInt.toString(2).length
    if (bitSize > MAX_PLAINTEXT_BIT_SIZE) {
        throw new RangeError("Plaintext size must be between 128 and 256 bits.")
    }

    // Convert user key to bytes
    const keyBytes = encodeKey(sender.userKey)
    let ct: Uint8Array

    // In case of 128 bits plaintext, encrypt it as the low part of the ct, and then encrypt the high part of the ct with zeros
    if (bitSize <= MAX_PLAINTEXT_BIT_SIZE / 2) {
        const plaintextBytes = new Uint8Array(BLOCK_SIZE) // Allocate a buffer of size 16 bytes
        writeBigUInt128BE(plaintextBytes, plaintextBigInt) // Write the uint128 value to the buffer as big-endian
        // Encrypt the plaintext using AES key
        const {ciphertext, r} = encrypt(keyBytes, plaintextBytes)

        // Encrypt the high part of the ct with zeros
        const zero = BigInt(0)
        const zeroBytes = new Uint8Array(BLOCK_SIZE)
        writeBigUInt128BE(zeroBytes, zero)
        const {ciphertext: ciphertextHigh, r: rHigh} = encrypt(keyBytes, zeroBytes)
        ct = new Uint8Array([...ciphertextHigh, ...rHigh, ...ciphertext, ...r])
        
    } else if (bitSize <= MAX_PLAINTEXT_BIT_SIZE) {
        const plaintextBytes = new Uint8Array(CT_SIZE) // Allocate a buffer of size 32 bytes
        writeBigUInt256BE(plaintextBytes, plaintextBigInt) // Write the uint256 value to the buffer as big-endian
        
        // Encrypt each part of the plaintext using AES key
        const resultHigh = encrypt(keyBytes, plaintextBytes.slice(0, BLOCK_SIZE))
        const resultLow = encrypt(keyBytes, plaintextBytes.slice(BLOCK_SIZE))
        
        // Now destructure
        const { ciphertext: ciphertextHigh, r: rHigh } = resultHigh
        const { ciphertext: ciphertextLow, r: rLow } = resultLow

        ct = new Uint8Array([...ciphertextHigh, ...rHigh, ...ciphertextLow, ...rLow])
    } else {
        throw new RangeError("Plaintext size must be 256 bits or smaller.")
    }

    // Convert the ciphertext to BigInt for signing
    const ctInt = BigInt('0x' + Buffer.from(ct).toString('hex'))
    const signature = signInputText(sender, contractAddress, functionSelector, ctInt)

    const ciphertextHigh = ct.slice(0, CT_SIZE)
    const ciphertextLow = ct.slice(CT_SIZE)

    // Convert Buffer to uint256 (BigInt) for Solidity compatibility
    const ciphertextHighUint = BigInt('0x' + Buffer.from(ciphertextHigh).toString('hex'))
    const ciphertextLowUint = BigInt('0x' + Buffer.from(ciphertextLow).toString('hex'))

    return {
        ciphertext: {
            ciphertextHigh: ciphertextHighUint,
            ciphertextLow: ciphertextLowUint
        },
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

export function buildBoolInputText(
    plaintext: boolean,
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string
): itBool {
    // Type validation for boolean
    if (typeof plaintext !== "boolean") {
        throw new TypeError("Plaintext for bool must be a boolean value.")
    }
    
    // Convert boolean to bigint (true = 1n, false = 0n)
    const value = plaintext ? 1n : 0n;
    
    return buildInputText(value, sender, contractAddress, functionSelector)
}

export function decryptUint(ciphertext: ctUint8 | ctUint16 | ctUint32 | ctUint64, userKey: string): bigint {
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

export function decryptUint8(ciphertext: ctUint8, userKey: string): bigint {
    return decryptUint(ciphertext, userKey)
}

export function decryptUint16(ciphertext: ctUint16, userKey: string): bigint {
    return decryptUint(ciphertext, userKey)
}

export function decryptUint32(ciphertext: ctUint32, userKey: string): bigint {
    return decryptUint(ciphertext, userKey)
}

export function decryptUint64(ciphertext: ctUint64, userKey: string): bigint {
    return decryptUint(ciphertext, userKey)
}

export function decryptUint128(ciphertext: ctUint128, userKey: string): bigint {
    return decryptUint(ciphertext, userKey)
}

export function decryptUint256(ciphertext: ctUint256, userKey: string): bigint {
    const high = decryptUint128(ciphertext.ciphertextHigh, userKey)
    const low = decryptUint128(ciphertext.ciphertextLow, userKey)
  
    // Reconstruct the full 256-bit unsigned value
    const unsigned = (high << 128n) | low;
    
    // Convert from unsigned to signed using two's complement for 256-bit
    const maxInt256 = (1n << 255n) - 1n;
    if (unsigned > maxInt256) {
        return unsigned - (1n << 256n);
    }
    return unsigned;
}

export function decryptString(ciphertext: ctString, userKey: string): string {
    let encodedStr = new Uint8Array()

    for (let i = 0; i < ciphertext.value.length; i++) {
        const decrypted = decryptUint(BigInt(ciphertext.value[i]), userKey)
        
        encodedStr = new Uint8Array([...encodedStr, ...encodeUint(decrypted)])
    }

    const decoder = new TextDecoder()

    return decoder
        .decode(encodedStr)
        .replace(/\0/g, '')
}

export function decryptBool(ciphertext: ctBool, userKey: string): boolean {
    const decrypted = decryptUint(ciphertext, userKey)
    // Convert bigint to boolean (0n = false, anything else = true)
    return decrypted !== 0n
}

export function generateRandomAesKeySizeNumber(): string {
    return crypto.randomBytes(BLOCK_SIZE).toString('hex')
}

export function writeBigUInt128BE(buffer: Uint8Array, value: bigint, offset: number = 0): void {
    const hexString = value.toString(HEX_BASE).padStart(CT_SIZE, '0')
    const bytes = Buffer.from(hexString, 'hex')
    const bufferArray = new Uint8Array(buffer)
    for (let i = 0; i < bytes.length; i++) {
        bufferArray[offset + i] = bytes[i]
    }
}

export function writeBigUInt256BE(buffer: Uint8Array, value: bigint, offset: number = 0): void {
    const hexString = value.toString(HEX_BASE).padStart(CT_SIZE * 2, '0')
    const bytes = Buffer.from(hexString, 'hex')
    const bufferArray = new Uint8Array(buffer)
    if (buffer.length > bytes.length) {
        offset = buffer.length - bytes.length
    }
    for (let i = 0; i < bytes.length; i++) {
        bufferArray[offset + i] = bytes[i]
    }
}

export function encodeString(str: string): Uint8Array {
    return new Uint8Array([...str.split('').map((char) => parseInt(char.codePointAt(0)?.toString(HEX_BASE)!, HEX_BASE))])
}

export function encodeKey(userKey: string): Uint8Array {
    const keyBytes = new Uint8Array(16)

    for (let i = 0; i < 32; i += 2) {
        keyBytes[i / 2] = parseInt(userKey.slice(i, i + 2), HEX_BASE)
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

export function encryptNumber(r: string | Uint8Array, key: Uint8Array): Uint8Array {
    // Ensure key size is 128 bits (16 bytes)
    if (key.length !== BLOCK_SIZE) {
        throw new RangeError("Key size must be 128 bits.")
    }

    // Create a new AES cipher using the provided key
    const cipher = crypto.createCipheriv('aes-128-ecb', key, null)

    // Encrypt the random value 'r' using AES in ECB mode
    const encryptedR = cipher.update(r)

    // Get the encrypted random value 'r' as a Buffer and ensure it's exactly 16 bytes
    return new Uint8Array(encryptedR).slice(0, BLOCK_SIZE)
}

export function getFuncSig(functionSig: string): Uint8Array {
    // Encode the string to bytes
    const functionBytes = toUtf8Bytes(functionSig)

    // Hash the function signature using Keccak-256
    const hash = keccak256(functionBytes)

    // Return first 4 bytes as Uint8Array
    return new Uint8Array(Buffer.from(hash.slice(2), 'hex').subarray(0, 4))
}

// Signed integer equivalents
export function buildInt8InputText(
    plaintext: bigint,
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string
): itInt8 {
    validateBigIntRange(plaintext, -128n, 127n, "int8")
    
    // Convert negative values to unsigned representation using two's complement
    let value = plaintext;
    if (plaintext < 0n) {
        value = (1n << 8n) + plaintext; // 256 + plaintext for 8-bit
    }
    
    return buildInputText(value, sender, contractAddress, functionSelector)
}

export function buildInt16InputText(
    plaintext: bigint,
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string
): itInt16 {
    validateBigIntRange(plaintext, -32768n, 32767n, "int16")
    
    // Convert negative values to unsigned representation using two's complement
    let value = plaintext;
    if (plaintext < 0n) {
        value = (1n << 16n) + plaintext; // 65536 + plaintext for 16-bit
    }
    
    return buildInputText(value, sender, contractAddress, functionSelector)
}

export function buildInt32InputText(
    plaintext: bigint,
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string
): itInt32 {
    validateBigIntRange(plaintext, -2147483648n, 2147483647n, "int32")
    
    // Convert negative values to unsigned representation using two's complement
    let value = plaintext;
    if (plaintext < 0n) {
        value = (1n << 32n) + plaintext; // 4294967296 + plaintext for 32-bit
    }
    
    return buildInputText(value, sender, contractAddress, functionSelector)
}

export function buildInt64InputText(
    plaintext: bigint,
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string
): itInt64 {
    validateBigIntRange(plaintext, -9223372036854775808n, 9223372036854775807n, "int64")
    
    // Convert negative values to unsigned representation using two's complement
    let value = plaintext;
    if (plaintext < 0n) {
        value = (1n << 64n) + plaintext; // 18446744073709551616 + plaintext for 64-bit
    }
    
    return buildInputText(value, sender, contractAddress, functionSelector)
}

export function buildInt128InputText(
    plaintext: bigint,
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string
): itInt128 {
    // Type and range validation for int128
    validateBigIntRange(plaintext, -(1n << 127n), (1n << 127n) - 1n, "int128")

    // Convert negative values to unsigned representation using two's complement
    let value = plaintext;
    if (plaintext < 0n) {
        value = (1n << 128n) + plaintext;
    }
    
    // Convert the plaintext to bytes using the new logic
    const plaintextBigInt = BigInt(value)
    const bitSize = plaintextBigInt.toString(2).length
    if (bitSize > MAX_PLAINTEXT_BIT_SIZE / 2) {
        throw new RangeError("Plaintext size must be 128 bits or smaller. To prepare a 256 bit plaintext, use buildInt256InputText instead.")
    }

    const plaintextBytes = new Uint8Array(BLOCK_SIZE) // Allocate a buffer of size 16 bytes
    writeBigUInt128BE(plaintextBytes, plaintextBigInt) // Write the uint128 value to the buffer as big-endian
    
    // Convert user key to bytes
    const keyBytes = encodeKey(sender.userKey)

    // Encrypt the plaintext using AES key
    const {ciphertext, r} = encrypt(keyBytes, plaintextBytes)
    const ct = new Uint8Array([...ciphertext, ...r])

    // Convert the ciphertext to BigInt
    const ctInt = BigInt('0x' + Buffer.from(ct).toString('hex'))

    const signature = signInputText(sender, contractAddress, functionSelector, ctInt);

    return {
        ciphertext: ctInt,
        signature: signature
    }
}

export function buildInt256InputText(
    plaintext: bigint,
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string
): itInt256 {
    // Type and range validation for int256
    validateBigIntRange(plaintext, -(1n << 255n), (1n << 255n) - 1n, "int256")

    // Convert to hex string and ensure it is 64 characters (32 bytes), handling two's complement for negatives
    let value = plaintext;
    if (plaintext < 0n) {
        value = (1n << 256n) + plaintext;
    }
    const hexString = value.toString(16).padStart(64, '0');

    // Split into two 16-byte (32-character) segments
    const high = hexString.slice(0, 32);
    const low = hexString.slice(32, 64);

    const itHigh = buildUint128InputText(BigInt(`0x${high}`), sender, contractAddress, functionSelector)
    const itLow = buildUint128InputText(BigInt(`0x${low}`), sender, contractAddress, functionSelector)

    return {
        ciphertext: {
            ciphertextHigh: itHigh.ciphertext,
            ciphertextLow: itLow.ciphertext
        },
        signature: itHigh.signature
    }
}

// Signed integer decrypt functions
export function decryptInt8(ciphertext: ctInt8, userKey: string): bigint {
    const unsigned = decryptUint(ciphertext, userKey)
    // Convert from unsigned to signed using two's complement
    if (unsigned > 127n) {
        return unsigned - 256n
    }
    return unsigned
}

export function decryptInt16(ciphertext: ctInt16, userKey: string): bigint {
    const unsigned = decryptUint(ciphertext, userKey)
    // Convert from unsigned to signed using two's complement
    if (unsigned > 32767n) {
        return unsigned - 65536n
    }
    return unsigned
}

export function decryptInt32(ciphertext: ctInt32, userKey: string): bigint {
    const unsigned = decryptUint(ciphertext, userKey)
    // Convert from unsigned to signed using two's complement
    if (unsigned > 2147483647n) {
        return unsigned - 4294967296n
    }
    return unsigned
}

export function decryptInt64(ciphertext: ctInt64, userKey: string): bigint {
    const unsigned = decryptUint(ciphertext, userKey)
    // Convert from unsigned to signed using two's complement
    if (unsigned > 9223372036854775807n) {
        return unsigned - 18446744073709551616n
    }
    return unsigned
}

export function decryptInt128(ciphertext: ctInt128, userKey: string): bigint {
    const unsigned = decryptUint(ciphertext, userKey)
    
    // Convert from unsigned to signed using two's complement for 128-bit
    const maxInt128 = (1n << 127n) - 1n;
    if (unsigned > maxInt128) {
        return unsigned - (1n << 128n);
    }
    return unsigned;
}

export function decryptInt256(ciphertext: ctInt256, userKey: string): bigint {
    const high = decryptInt128(ciphertext.ciphertextHigh, userKey)
    const low = decryptInt128(ciphertext.ciphertextLow, userKey)
  
    // Reconstruct the full 256-bit unsigned value
    const unsigned = (high << 128n) | low;
    
    // Convert from unsigned to signed using two's complement for 256-bit
    const maxInt256 = (1n << 255n) - 1n;
    if (unsigned > maxInt256) {
        return unsigned - (1n << 256n);
    }
    return unsigned;
}
