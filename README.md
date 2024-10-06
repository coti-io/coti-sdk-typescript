# COTI V2 Confidentiality Preserving L2 | SDKs and Examples

All repositories specified below contain smart contracts that implement confidentiality features using the COTI V2
protocol.
The contracts provide examples for various use cases, such as Non-Fungible Tokens (NFTs), ERC20 tokens, Auction, and
Identity management.

These contracts demonstrate how to leverage the confidentiality features of the COTI V2 protocol to enhance privacy and
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

# COTI v2 Typescript SDK

> [!NOTE]
> Please refer to the latest [tags](https://github.com/coti-io/coti-sdk-typescript/tags) to find the most stable version
> to use.
> All tagged versions are available to install via [npmjs](https://www.npmjs.com/package/@coti-io/coti-sdk-typescript)

The COTI Typescript SDK is composed of two main components:

1. The `crypto_utils.ts`: used for cryptographic operations.

2. The `ether_utils.ts` : used for ethers related operations

3. Typescript classes to interact with the COTI network. These are located in the [src/account](src/account) directory.
   The following are provided:

* `confidential-account.ts`: designed to handle confidential data by providing methods for encryption and decryption, as
  well as onboarding new wallets. It utilizes cryptographic functions to ensure the security of data on the COTI
  network.

* `onboard_contract.ts`: interact with the onboarding smart contract. The address and ABI allow a web3-enabled
  application to connect to the contract, listen for events, and call the `OnboardAccount` function to onboard new
  accounts.

* `onboard.ts`: facilitates the onboarding of new users by generating cryptographic keys, signing data, and interacting
  with a blockchain smart contract. The `onboard` function automates the entire process, ensuring secure onboarding and
  key management.

# crypto_utils.ts

This TypeScript library, `crypto_utils.ts`, provides cryptographic functions to interact with the COTI network. Below is
an overview of its components and functions:

## Dependencies

- `crypto`: Node.js built-in module for cryptographic operations.
- `ethers`: Ethereum library for various utilities, including `solidityPackedKeccak256`, `SigningKey`, `getBytes`,
  and `BaseWallet`.

## Constants

- `block_size`: AES block size in bytes (16).
- `hexBase`: Base for hexadecimal representation (16).

## Functions

### AES Encryption/Decryption

### 1. `encrypt(key: Buffer, plaintext: Buffer)`

Encrypts the given plaintext using AES in ECB mode with the provided key.

- **Parameters**:
    - `key`: 128-bit (16 bytes) key for AES encryption.
    - `plaintext`: Data to be encrypted (must be 128 bits or smaller).
- **Returns**:
    - `ciphertext`: Encrypted data.
    - `r`: Random value used during encryption.

### 2. `decrypt(key: Buffer, r: Buffer, ciphertext: Buffer)`

Decrypts the given ciphertext using AES in ECB mode with the provided key and random value.

- **Parameters**:
    - `key`: 128-bit (16 bytes) key for AES decryption.
    - `r`: Random value used during encryption.
    - `ciphertext`: Encrypted data to be decrypted.
- **Returns**:
    - `plaintext`: Decrypted data.

### 3. `generateAesKey()`

Generates a random 128-bit AES key.

**Returns:**

- `key`: The generated 128-bit AES key.

### RSA Key Management

### 1. `generateRSAKeyPair()`

Generates a new RSA key pair.

- **Returns**:
    - `publicKey`: RSA public key in DER format.
    - `privateKey`: RSA private key in DER format.

### 2. `decryptRSA(privateKey: Buffer, ciphertext: Buffer)`

Decrypts the given ciphertext using RSA-OAEP with the provided private key.

- **Parameters**:
    - `privateKey`: RSA private key in PEM format.
    - `ciphertext`: Data to be decrypted.
- **Returns**:
    - Decrypted data.

### Input text decryption/encryption and Signing

### 1. `sign(message: string, privateKey: string)`

Signs the given message using the provided private key.

- **Parameters**:
    - `message`: Message to be signed.
    - `privateKey`: Signer's private key.
- **Returns**:
    - Signature as a concatenation of `r`, `s`, and `v` values.

### 2. `signInputText(wallet: BaseWallet, userKey: string, contractAddress: string , functionSelector: string, ct: Buffer)`

Signs the given message using the provided private key.

- **Parameters**:
    - `wallet`: an ether wallet to sign the ether transaction.
    - `privateKey`: Signer's private key.
    - `contractAddress`: the contract address.
    - `functionSelector`: the function signature.
    - `ct`: The ciphertext.
- **Returns**:
    - `signature`: The generated signature.

### 3.`buildInputText(plaintext: bigint, sender: { wallet: BaseWallet; userKey: string }, contractAddress: string, functionSelector: string)`

Builds input text by encrypting the plaintext and signing it.
**Parameters:**

- `plaintext`: The plaintext message.
- `sender`: The sender's wallet and userKey.
- `contractAddress`: The contract address.
- `functionSelector`: The function signature.

**Returns:**

- `intCipherText`: The integer representation of the ciphertext.
- `signature`: The generated signature.

### 4.`buildStringInputText((plaintext: string, sender: { wallet: BaseWallet; userKey: string }, contractAddress: string, functionSelector: string)`

Builds input text by encrypting the plaintext and signing it.
**Parameters:**

- `plaintext`: The plaintext string message.
- `sender`: The sender's wallet and userKey.
- `contractAddress`: The contract address.
- `functionSelector`: The function signature.

**Returns:**

- `inputText`: An object of the form { "ciphertext": { "value": int[] }, "signature": bytes[] }

### 5. `decryptUint(ciphertext: bigint, userKey: string)`

Decrypts a value stored in a contract using a user key.

**Parameters:**

- `ciphertext`: The value to be decrypted.
- `userKey`: The user's AES key.

**Returns:**

- `result`: The decrypted value.

### 6. `decryptString(ciphertext: Array<bigint>, userKey: string)`

Decrypts a value stored in a contract using a user key.

**Parameters:**

- `ciphertext`: An object of the form { "value": int[] } where each cell holds up to 8 characters (padded at the end with zeroes) encrypted
- `userKey`: The user's AES key.

**Returns:**

- `result`: The decrypted string.

#### To report issues, please create a [github issue](https://github.com/coti-io/coti-sdk-typescript/issues)
