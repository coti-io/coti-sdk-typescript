import forge from 'node-forge'
import {BaseWallet, ethers, getBytes, SigningKey, solidityPackedKeccak256} from "ethers"

const BLOCK_SIZE = 16 // AES block size in bytes
const HEX_BASE = 16

export function encrypt(key: Uint8Array, plaintext: Uint8Array): { ciphertext: Uint8Array; r: Uint8Array } {
    // Ensure plaintext is smaller than 128 bits (16 bytes)
    if (plaintext.length > BLOCK_SIZE) {
        throw new RangeError("Plaintext size must be 128 bits or smaller.")
    }

    // Generate a random value 'r' of the same length as the block size
    const r = forge.random.getBytesSync(BLOCK_SIZE)

    // Get the encrypted random value 'r'
    const encryptedR = encryptRandomNumber(r, key)

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
    const encryptedR = encryptRandomNumber(r, key)

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

export function keccak256(publicKey: Buffer) {
    return ethers.keccak256(publicKey);
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
) {
    if (plaintext >= BigInt(2) ** BigInt(128)) {
        throw new RangeError("Plaintext size must be 128 bits or smaller.")
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

    return {ctInt, signature}
}

export async function buildStringInputText(
    plaintext: string,
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string
) {
    let encoder = new TextEncoder()

    let encodedStr = encoder.encode(plaintext)

    let encryptedStr = new Array<{ ciphertext: bigint, signature: Uint8Array }>(plaintext.length)

    for (let i = 0; i < plaintext.length; i++) {
        const {ctInt, signature} = buildInputText(BigInt(encodedStr[i]), sender, contractAddress, functionSelector)
        encryptedStr[i] = {ciphertext: ctInt, signature}
    }

    return encryptedStr
}

export function decryptUint(ciphertext: bigint, userKey: string): bigint {
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

export function decryptString(ciphertext: Array<bigint>, userKey: string): string {
    let decryptedStr = new Array<number>(ciphertext.length)

    for (let i = 0; i < ciphertext.length; i++) {
        decryptedStr[i] = Number(decryptUint(ciphertext[i], userKey))
    }

    let decoder = new TextDecoder()

    return decoder.decode(new Uint8Array(decryptedStr))
}

export function generateAesKey(): string {
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

function encryptRandomNumber(r: string | Uint8Array, key: Uint8Array) {
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
