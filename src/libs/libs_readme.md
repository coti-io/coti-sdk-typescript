# crypto.ts

This TypeScript library, `crypto.ts`, provides cryptographic functions to interact with the COTI network. Below is an overview of its components and functions:

## Dependencies
- `crypto`: Node.js built-in module for cryptographic operations.
- `ethers`: Ethereum library for various utilities, including `solidityPackedKeccak256`, `SigningKey`, `getBytes`, and `BaseWallet`.

## Constants
- `block_size`: AES block size in bytes (16).
- `hexBase`: Base for hexadecimal representation (16).

## Functions

### AES Encryption/Decryption
#### `encrypt(key: Buffer, plaintext: Buffer)`
Encrypts the given plaintext using AES in ECB mode with the provided key.
- **Parameters**: 
  - `key`: 128-bit (16 bytes) key for AES encryption.
  - `plaintext`: Data to be encrypted (must be 128 bits or smaller).
- **Returns**: 
  - `ciphertext`: Encrypted data.
  - `r`: Random value used during encryption.

#### `decrypt(key: Buffer, r: Buffer, ciphertext: Buffer)`
Decrypts the given ciphertext using AES in ECB mode with the provided key and random value.
- **Parameters**: 
  - `key`: 128-bit (16 bytes) key for AES decryption.
  - `r`: Random value used during encryption.
  - `ciphertext`: Encrypted data to be decrypted.
- **Returns**: 
  - `plaintext`: Decrypted data.

### RSA Key Management
#### `generateRSAKeyPair()`
Generates a new RSA key pair.
- **Returns**: 
  - `publicKey`: RSA public key in DER format.
  - `privateKey`: RSA private key in DER format.

#### `decryptRSA(privateKey: Buffer, ciphertext: Buffer)`
Decrypts the given ciphertext using RSA-OAEP with the provided private key.
- **Parameters**: 
  - `privateKey`: RSA private key in PEM format.
  - `ciphertext`: Data to be decrypted.
- **Returns**: 
  - Decrypted data.

### Decryption and Signing
#### `decryptValue(ctAmount: bigint, userKey: string)`
Decrypts the given ciphertext amount using the user's key.
- **Parameters**: 
  - `ctAmount`: Ciphertext amount in `bigint`.
  - `userKey`: User's key in hexadecimal format.
- **Returns**: 
  - Decrypted value as an integer.

#### `sign(message: string, privateKey: string)`
Signs the given message using the provided private key.
- **Parameters**: 
  - `message`: Message to be signed.
  - `privateKey`: Signer's private key.
- **Returns**: 
  - Signature as a concatenation of `r`, `s`, and `v` values.

This library provides essential cryptographic operations such as encryption, decryption, key generation, and message signing, enabling secure interactions with the COTI network.
