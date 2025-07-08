import forge from 'node-forge'
import {
    BaseWallet,
    getBytes,
    SigningKey,
    solidityPackedKeccak256
} from "ethers"
import {
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
const HEX_BASE = 16
const EIGHT_BYTES = 8

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

export function decrypt(key: Uint8Array, r: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    if (ciphertext.length !== BLOCK_SIZE) {
        throw new RangeError("Ciphertext size must be 128 bits.")
    }

    // Ensure random size is 128 bits (16 bytes)
    if (r.length != BLOCK_SIZE) {
        throw new RangeError("Random size must be 128 bits.")
    }

    // Get the encrypted random value 'r'
    const encryptedR = encryptNumber(r, key)

    // XOR the encrypted random value 'r' with the ciphertext to obtain the plaintext
    const plaintext = new Uint8Array(BLOCK_SIZE)

    for (let i = 0; i < encryptedR.length; i++) {
        plaintext[i] = encryptedR[i] ^ ciphertext[i]
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
): itUint8 | itUint16 | itUint32 | itUint64 {
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

    // Convert to hex string and ensure it is 32 characters (16 bytes)
    const hexString = plaintext.toString(16).padStart(32, '0');

    // Split into two 8-byte (16-character) segments
    const high = hexString.slice(0, 16);
    const low = hexString.slice(16, 32);

    const itHigh = buildInputText(BigInt(`0x${high}`), sender, contractAddress, functionSelector)
    const itLow = buildInputText(BigInt(`0x${low}`), sender, contractAddress, functionSelector)

    return {
        ciphertext: {
            high: itHigh.ciphertext,
            low: itLow.ciphertext
        },
        signature: [itHigh.signature, itLow.signature]
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
    
    // Convert to hex string and ensure it is 64 characters (32 bytes)
    const hexString = plaintext.toString(16).padStart(64, '0');
  
    // Split into two 16-byte (-character) segments
    const high = hexString.slice(0, 32);
    const low = hexString.slice(32, 64);

    const itHigh = buildUint128InputText(BigInt(`0x${high}`), sender, contractAddress, functionSelector)
    const itLow = buildUint128InputText(BigInt(`0x${low}`), sender, contractAddress, functionSelector)

    return {
        ciphertext: {
            high: itHigh.ciphertext,
            low: itLow.ciphertext
        },
        signature: [itHigh.signature, itLow.signature]
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
    const high = decryptUint(ciphertext.high, userKey)
    const low = decryptUint(ciphertext.low, userKey)
  
    // Convert both high and low parts to hex strings, ensuring they are 16 characters (8 bytes) long
    let highHex = high.toString(16).padStart(16, '0');
    let lowHex = low.toString(16).padStart(16, '0');
  
    // Concatenate and convert back to a single bigint
    return BigInt(`0x${highHex + lowHex}`);
}

export function decryptUint256(ciphertext: ctUint256, userKey: string): bigint {
    const high = decryptUint128(ciphertext.high, userKey)
    const low = decryptUint128(ciphertext.low, userKey)
  
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

export function generateRandomAesKeySizeNumber(): string {
    return forge.random.getBytesSync(BLOCK_SIZE)
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

    // Get the encrypted random value 'r' as a Buffer and ensure it's exactly 16 bytes
    const encryptedR = encodeString(cipher.output.data).slice(0, BLOCK_SIZE)

    return encryptedR
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

    // Convert to hex string and ensure it is 32 characters (16 bytes), handling two's complement for negatives
    let value = plaintext;
    if (plaintext < 0n) {
        value = (1n << 128n) + plaintext;
    }
    const hexString = value.toString(16).padStart(32, '0');

    // Split into two 8-byte (16-character) segments
    const high = hexString.slice(0, 16);
    const low = hexString.slice(16, 32);

    const itHigh = buildInputText(BigInt(`0x${high}`), sender, contractAddress, functionSelector)
    const itLow = buildInputText(BigInt(`0x${low}`), sender, contractAddress, functionSelector)

    return {
        ciphertext: {
            high: itHigh.ciphertext,
            low: itLow.ciphertext
        },
        signature: [itHigh.signature, itLow.signature]
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
            high: itHigh.ciphertext,
            low: itLow.ciphertext
        },
        signature: [itHigh.signature, itLow.signature]
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
    const high = decryptUint(ciphertext.high, userKey)
    const low = decryptUint(ciphertext.low, userKey)
  
    // Convert both high and low parts to hex strings, ensuring they are 16 characters (8 bytes) long
    let highHex = high.toString(16).padStart(16, '0');
    let lowHex = low.toString(16).padStart(16, '0');
  
    // Concatenate and convert back to a single bigint
    const unsigned = BigInt(`0x${highHex + lowHex}`);
    
    // Convert from unsigned to signed using two's complement for 128-bit
    const maxInt128 = (1n << 127n) - 1n;
    if (unsigned > maxInt128) {
        return unsigned - (1n << 128n);
    }
    return unsigned;
}

export function decryptInt256(ciphertext: ctInt256, userKey: string): bigint {
    const high = decryptUint128(ciphertext.high, userKey)
    const low = decryptUint128(ciphertext.low, userKey)
  
    // Reconstruct the full 256-bit unsigned value
    const unsigned = (high << 128n) | low;
    
    // Convert from unsigned to signed using two's complement for 256-bit
    const maxInt256 = (1n << 255n) - 1n;
    if (unsigned > maxInt256) {
        return unsigned - (1n << 256n);
    }
    return unsigned;
}
