import crypto from "crypto"
import {BaseWallet, ethers, getBytes, SigningKey, solidityPackedKeccak256} from "ethers"
import * as fs from "node:fs";

const block_size = 16 // AES block size in bytes
const hexBase = 16

export function encrypt(key: Buffer, plaintext: Buffer): { ciphertext: Buffer; r: Buffer } {
    // Ensure plaintext is smaller than 128 bits (16 bytes)
    if (plaintext.length > block_size) {
        throw new RangeError("Plaintext size must be 128 bits or smaller.")
    }
    // Ensure key size is 128 bits (16 bytes)
    if (key.length != block_size) {
        throw new RangeError("Key size must be 128 bits.")
    }
    // Create a new AES cipher using the provided key
    const cipher = crypto.createCipheriv("aes-128-ecb", key, null)

    // Generate a random value 'r' of the same length as the block size
    const r = crypto.randomBytes(block_size)

    // Encrypt the random value 'r' using AES in ECB mode
    const encryptedR = cipher.update(r)

    // Pad the plaintext with zeros if it's smaller than the block size
    const plaintext_padded = Buffer.concat([Buffer.alloc(block_size - plaintext.length), plaintext])

    // XOR the encrypted random value 'r' with the plaintext to obtain the ciphertext
    const ciphertext = Buffer.alloc(encryptedR.length)
    for (let i = 0; i < encryptedR.length; i++) {
        ciphertext[i] = encryptedR[i] ^ plaintext_padded[i]
    }

    return {ciphertext, r}
}

export function decrypt(key: Buffer, r: Buffer, ciphertext: Buffer): Buffer {
    if (ciphertext.length !== block_size) {
        throw new RangeError("Ciphertext size must be 128 bits.")
    }

    // Ensure key size is 128 bits (16 bytes)
    if (key.length != block_size) {
        throw new RangeError("Key size must be 128 bits.")
    }

    // Ensure random size is 128 bits (16 bytes)
    if (r.length != block_size) {
        throw new RangeError("Random size must be 128 bits.")
    }

    // Create a new AES decipher using the provided key
    const cipher = crypto.createCipheriv("aes-128-ecb", key, null)

    // Encrypt the random value 'r' using AES in ECB mode
    const encryptedR = cipher.update(r)

    // XOR the encrypted random value 'r' with the ciphertext to obtain the plaintext
    const plaintext = Buffer.alloc(encryptedR.length)
    for (let i = 0; i < encryptedR.length; i++) {
        plaintext[i] = encryptedR[i] ^ ciphertext[i]
    }

    return plaintext
}

export function generateRSAKeyPair(): crypto.KeyPairSyncResult<Buffer, Buffer> {
    // Generate a new RSA key pair
    return crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: "spki",
            format: "der", // Specify 'der' format for binary data
        },
        privateKeyEncoding: {
            type: "pkcs8",
            format: "der", // Specify 'der' format for binary data
        },
    })
}

export function decryptRSA(privateKey: Buffer, ciphertext: Buffer): Buffer {
    // Load the private key in PEM format
    let privateKeyPEM = privateKey.toString("base64")
    privateKeyPEM = `-----BEGIN PRIVATE KEY-----\n${privateKeyPEM}\n-----END PRIVATE KEY-----`
    // Decrypt the ciphertext using RSA-OAEP
    return crypto.privateDecrypt(
        {
            key: privateKeyPEM,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        ciphertext
    )
}


export function sign(message: string, privateKey: string) {
    const key = new SigningKey(privateKey)
    const sig = key.sign(message)
    return Buffer.concat([getBytes(sig.r), getBytes(sig.s), getBytes(`0x0${sig.v - 27}`)])
}

export function keccak256(publicKey: Buffer) {
    return ethers.keccak256(publicKey);
}

export function signInputText(sender: {
    wallet: BaseWallet;
    userKey: string
}, contractAddress: string, functionSelector: string, ct: Buffer) {
    const message = solidityPackedKeccak256(
        ["address", "address", "bytes4", "uint256"],
        [sender.wallet.address, contractAddress, functionSelector, BigInt("0x" + ct.toString("hex"))]
    )

    return sign(message, sender.wallet.privateKey);
}

export function buildInputText(
    plaintext: bigint,
    sender: { wallet: BaseWallet; userKey: string },
    contractAddress: string,
    functionSelector: string
) {
    // Convert the plaintext to bytes
    const plaintextBytes = Buffer.alloc(8) // Allocate a buffer of size 8 bytes
    plaintextBytes.writeBigUInt64BE(plaintext) // Write the uint64 value to the buffer as little-endian

    // Encrypt the plaintext using AES key
    const {ciphertext, r} = encrypt(Buffer.from(sender.userKey, "hex"), plaintextBytes)
    const ct = Buffer.concat([ciphertext, r])

    const signature = signInputText(sender, contractAddress, functionSelector, ct);

    // Convert the ciphertext to BigInt
    const ctInt = BigInt("0x" + ct.toString("hex"))

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

    let encryptedStr = new Array<{ ciphertext: bigint, signature: Buffer }>(plaintext.length)

    for (let i = 0; i < plaintext.length; i++) {
        const {ctInt, signature} = buildInputText(BigInt(encodedStr[i]), sender, contractAddress, functionSelector)
        encryptedStr[i] = {ciphertext: ctInt, signature}
    }

    return encryptedStr
}

export function generateAesKey() {
    return crypto.randomBytes(block_size).toString("hex")
}

export function loadAesKey(filePath: string): Buffer {
    const hexKey = fs.readFileSync(filePath, 'utf8').trim();
    const key = Buffer.from(hexKey, 'hex');
    if (key.length !== block_size) {
        throw new Error(`Invalid key length: ${key.length} bytes, must be ${block_size} bytes`);
    }
    return key;
}

export function writeAesKey(filePath: string, key: Buffer): void {
    if (key.length !== block_size) {
        throw new Error(`Invalid key length: ${key.length} bytes, must be ${block_size} bytes`);
    }
    const hexKey = key.toString('hex');
    fs.writeFileSync(filePath, hexKey);
}


