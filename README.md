# COTI Privacy  Preserving L2 | SDKs and Examples

All repositories specified below contain smart contracts that implement confidentiality features using the COTI
protocol.
The contracts provide examples for various use cases, such as Non-Fungible Tokens (NFTs), ERC20 tokens, Auction, and
Identity management.

These contracts demonstrate how to leverage the confidentiality features of the COTI protocol to enhance privacy and
security in decentralized applications.
The contracts are of Solidity and can be compiled and deployed using popular development tools like Hardhat and
Foundry (Work in progress).

#### Important Links:

[Docs](https://docs.coti.io) | [Devnet Explorer](https://explorer-devnet.coti.io) | [Discord](https://discord.gg/cuCykh8P4m) | [Faucet](https://faucet.coti.io)

Interact with the network using any of the following:

1. [Python SDK](https://github.com/coti-io/coti-sdk-python) | [Python SDK Examples](https://github.com/coti-io/coti-sdk-python-examples)
2. [Typescript SDK](https://github.com/coti-io/coti-sdk-typescript) | [Typescript SDK Examples](https://github.com/coti-io/coti-sdk-typescript-examples)
3. [Hardhat Dev Environment](https://github.com/coti-io/confidentiality-contracts)

The following contracts are available in each of the packages:

| Contract                       |            | python sdk | hardhat sdk | typescript sdk | Contract Description                                                                                                                          |
|--------------------------------|------------|------------|-------------|----------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| `AccountOnboard`               | deployment | ✅ *        | ✅           | ❌              | Onboard a EOA account - During onboard network creates AES unique for that EOA which is used for decrypting values sent back from the network |
| `AccountOnboard`               | execution  | ✅          | ✅           | ✅              | "                                                                                                                                             |
| `ERC20Example`                 | deployment | ✅          | ✅           | ❌              | Confidential ERC20 - deploy and transfer encrypted amount of funds                                                                            |
| `ERC20Example`                 | execution  | ✅          | ✅           | ✅              | "                                                                                                                                             |
| `NFTExample`                   | deployment | ❌          | ✅           | ❌              | Confidential NFT example - saving encrypted data                                                                                              |
| `NFTExample`                   | execution  | ❌          | ✅           | ❌              | "                                                                                                                                             |
| `ConfidentialAuction`          | deployment | ❌          | ✅           | ❌              | Confidential auction - encrypted bid amount                                                                                                   |
| `ConfidentialAuction`          | execution  | ❌          | ✅           | ❌              | "                                                                                                                                             |
| `ConfidentialIdentityRegistry` | deployment | ❌          | ✅           | ❌              | Confidential Identity Registry - Encrypted identity data                                                                                      |
| `ConfidentialIdentityRegistry` | execution  | ❌          | ✅           | ❌              | "                                                                                                                                             |
| `DataOnChain`                  | deployment | ✅          | ❌           | ❌              | Basic encryption and decryption - Good place to start explorining network capabilties                                                         |
| `DataOnChain`                  | execution  | ✅          | ❌           | ✅              | "                                                                                                                                             |
| `Precompile`                   | deployment | ✅          | ✅           | ❌              | Thorough examples of the precompile functionality                                                                                             |
| `Precompile`                   | execution  | ✅          | ✅           | ❌              | "                                                                                                                                             |-              |              

(*) no deployment needed (system contract)

> [!NOTE]  
> Due to the nature of ongoing development, future version might break existing functionality

### Faucet

🤖 To request devnet/testnet funds use our [faucet](https://faucet.coti.io)

# COTI Typescript SDK

> [!NOTE]
> Please refer to the latest [tags](https://github.com/coti-io/coti-sdk-typescript/tags) to find the most stable version
> to use.
> All tagged versions are available to install via [npmjs](https://www.npmjs.com/package/@coti-io/coti-sdk-typescript)

The COTI Typescript SDK is mainly `crypto_utils.ts`: used for cryptographic operations.

(Ethers methods and mandatory wallet management operations, previously ethers_utils.ts, moved to [coti-ethers](https://github.com/coti-io/coti-ethers/))

# CRYPTO Utilities (crypto_utils.ts)

This TypeScript library provides a set of encryption, decryption, and cryptographic utilities, including RSA and AES encryption, message signing, and key handling functions. The utilities are primarily designed to work with cryptographic operations for secure communication and message signing, particularly within Ethereum smart contracts or similar environments.

## Features

- **AES encryption** with ECB mode for data of fixed block sizes.
- **RSA key pair generation**, encryption, and decryption using RSA-OAEP with SHA-256.
- **Signing of Ethereum transactions** using the `ethers` library's signing mechanisms.
- Utilities for encoding/decoding, padding, and cryptographic data manipulation.

## Installation

Ensure you have Node.js and npm installed. Then, install the necessary dependencies:

```bash
npm install node-forge ethers
```

## Functions

### `encrypt(key: Uint8Array, plaintext: Uint8Array): { ciphertext: Uint8Array; r: Uint8Array }`

Encrypts a given plaintext using the provided AES key. The plaintext is XORed with an encrypted random value.

- **Parameters:**
  - `key`: The AES encryption key (16 bytes).
  - `plaintext`: The data to be encrypted (must be 16 bytes or smaller).
- **Returns:** An object containing:
  - `ciphertext`: The encrypted data.
  - `r`: The random value used in the encryption process.

### `decrypt(key: Uint8Array, r: Uint8Array, ciphertext: Uint8Array): Uint8Array`

Decrypts a ciphertext using the provided AES key and random value `r`.

- **Parameters:**
  - `key`: The AES encryption key (16 bytes).
  - `r`: The random value used during encryption (16 bytes).
  - `ciphertext`: The encrypted data (16 bytes).
- **Returns:** The decrypted plaintext.

### `generateRSAKeyPair(): { publicKey: Uint8Array; privateKey: Uint8Array }`

Generates a new RSA key pair (2048 bits) and returns the keys in DER format.

- **Returns:** An object containing:
  - `publicKey`: The RSA public key (DER-encoded).
  - `privateKey`: The RSA private key (DER-encoded).

### `decryptRSA(privateKey: Uint8Array, ciphertext: string): string`

Decrypts an RSA-encrypted ciphertext using the provided private key.

- **Parameters:**
  - `privateKey`: The RSA private key (DER-encoded).
  - `ciphertext`: The encrypted ciphertext as a hex string.
- **Returns:** The decrypted message as a string.

### `sign(message: string, privateKey: string): Uint8Array`

Signs a message using the provided Ethereum private key.

- **Parameters:**
  - `message`: The message to be signed.
  - `privateKey`: The Ethereum private key.
- **Returns:** A signature as a `Uint8Array` containing `r`, `s`, and `v` values.

### `signInputText(sender, contractAddress, functionSelector, ct: bigint): Uint8Array`

Generates a signed message hash for Ethereum contract interactions.

- **Parameters:**
  - `sender`: The sender's information containing their wallet and user key.
  - `contractAddress`: The Ethereum contract address.
  - `functionSelector`: The function selector (bytes4) for the contract function.
  - `ct`: The ciphertext (big integer).
- **Returns:** A signature for the provided message.

### `buildInputText(plaintext: bigint, sender, contractAddress, functionSelector): itUint`

Encrypts a plaintext (up to 64 bits) and generates a signed transaction payload.

- **Parameters:**
  - `plaintext`: The data to be encrypted (must be smaller than 64 bits).
  - `sender`: The sender's information containing their wallet and user key.
  - `contractAddress`: The Ethereum contract address.
  - `functionSelector`: The function selector for the contract function.
- **Returns:** An `itUint` object containing the encrypted ciphertext and signature.

### `buildStringInputText(plaintext: string, sender, contractAddress, functionSelector): itString`

Encrypts a plaintext string and generates a signed transaction payload.

- **Parameters:**
  - `plaintext`: The data to be encrypted (string).
  - `sender`: The sender's information containing their wallet and user key.
  - `contractAddress`: The Ethereum contract address.
  - `functionSelector`: The function selector for the contract function.
- **Returns:** An `itString` object containing the encrypted ciphertext and signature.

### `decryptUint(ciphertext: ctUint, userKey: string): bigint`

Decrypts an AES-encrypted ciphertext and returns the original plaintext as a `bigint`.

- **Parameters:**
  - `ciphertext`: The encrypted ciphertext.
  - `userKey`: The user key for AES decryption.
- **Returns:** The decrypted plaintext as a `bigint`.

### `decryptString(ciphertext: { value: bigint[] }, userKey: string): string`

Decrypts an AES-encrypted ciphertext representing a string.

- **Parameters:**
  - `ciphertext`: An object containing the encrypted ciphertext as a list of bigints.
  - `userKey`: The user key for AES decryption.
- **Returns:** The decrypted plaintext as a string.

### `generateRandomAesKeySizeNumber(): string`

Generates a random 128-bit AES key.

- **Returns:** A string containing the random bytes.

### Utility Functions

- **`encodeString(str: string): Uint8Array`**: Converts a string to a `Uint8Array` encoded with the hexadecimal representation of each character.
- **`encodeKey(userKey: string): Uint8Array`**: Encodes a user key (hex string) to a `Uint8Array`.
- **`encodeUint(plaintext: bigint): Uint8Array`**: Converts a bigint to a `Uint8Array`.
- **`decodeUint(plaintextBytes: Uint8Array): bigint`**: Converts a `Uint8Array` to a bigint.
- **`encryptNumber(r: string | Uint8Array, key: Uint8Array): Uint8Array`**: Encrypts a random value `r` using AES in ECB mode.

## Constants

- `BLOCK_SIZE`: AES block size in bytes (16).
- `HEX_BASE`: Base used for hexadecimal conversion (16).
- `EIGHT_BYTES`: Constant representing 8 bytes (used for processing data in chunks).


#### To report issues, please create a [github issue](https://github.com/coti-io/coti-sdk-typescript/issues)
