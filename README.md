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
> Please refer to the latest [tags](https://github.com/coti-io/coti-sdk-typescript/tags) to find the most stable version to use. 
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

### 4.`writeAesKey(file_path, key)`

Writes a 128-bit AES key to a file in hex-encoded format.
**Parameters:**

- `filePath`: Path to the file where the key will be written.
- `key`: The 128-bit AES key.

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

### 1. `decryptValue(ctAmount: bigint, userKey: string)`

Decrypts the given ciphertext amount using the user's key.

- **Parameters**:
    - `ctAmount`: Ciphertext amount in `bigint`.
    - `userKey`: User's key in hexadecimal format.
- **Returns**:
    - Decrypted value as an integer.

### 2. `sign(message: string, privateKey: string)`

Signs the given message using the provided private key.

- **Parameters**:
    - `message`: Message to be signed.
    - `privateKey`: Signer's private key.
- **Returns**:
    - Signature as a concatenation of `r`, `s`, and `v` values.

### 3. `signInputText(wallet: BaseWallet, userKey: string, contractAddress: string , functionSelector: string, ct: Buffer)`

Signs the given message using the provided private key.

- **Parameters**:
    - `wallet`: an ether wallet to sign the ether transaction.
    - `privateKey`: Signer's private key.
    - `contractAddress`: the contract address.
    - `functionSelector`: the function signature.
    - `ct`: The ciphertext.
- **Returns**:
    - `signature`: The generated signature.

### 4.`buildInputText(plaintext: bigint, sender: { wallet: BaseWallet; userKey: string }, contractAddress: string, functionSelector: string)`

Builds input text by encrypting the plaintext and signing it.
**Parameters:**

- `plaintext`: The plaintext message.
- `sender`: The sender's wallet and userKey.
- `contractAddress`: The contract address.
- `functionSelector`: The function signature.

**Returns:**

- `intCipherText`: The integer representation of the ciphertext.
- `signature`: The generated signature.

### 5.`buildStringInputText((plaintext: string, sender: { wallet: BaseWallet; userKey: string }, contractAddress: string, functionSelector: string)`

Builds input text by encrypting the plaintext and signing it.
**Parameters:**

- `plaintext`: The plaintext string message.
- `sender`: The sender's wallet and userKey.
- `contractAddress`: The contract address.
- `functionSelector`: The function signature.

**Returns:**

- `intCipherText`: The integer representation of the ciphertext.
- `signature`: The generated signature.

# ether_utils.ts

This TypeScript library, `ethers_utils.ts`, provides ethers functionality to interact with the COTI-v2 network. Below is
an overview of its components and functions:

### 1.`printNetworkDetails(provider: Provider)`

Prints the network details of the provider instance.

**Parameters:**

- `provider`: An instance of ethers provider.

### 2.`printAccountDetails(provider: Provider, address: string)`

Prints the account details of the default account in the Web3 instance.

**Parameters:**

- `provider`: An instance of ethers provider.
- `address`: an Ethereum EOA account.

### 3. `getAccountBalance(address: string, provider: Provider)`

Retrieves the native balance of an address in wei.

**Parameters:**

- `provider`: An instance of ethers provider.
- `address`: The address to check the balance of (default is the default account).

**Returns:**

- `result`: The address balance in wei.

### 4. `initEtherProvider(rpcUrl: string = "https://devnet.coti.io/rpc")`

Initializes the ethers RPC provider instance with the given node address.

**Parameters:**

- `rpcUrl`: The RPC address of the COTI node.

**Returns:**

- `provider`: The initialized Ether JsonRpcProvider instance.

### 5. `validateAddress(address: string)`

Validates and returns the checksum address for a given address.

**Parameters:**

- `address`: The address to be validated.

**Returns:**

- `result`: A map with `valid` (boolean) and `safe` (checksum address).

### 6. `getLatestBlock(provider: Provider)`

Retrieves the latest block from the COTI network.

**Parameters:**

- `provider`: An instance of ethers provider.

**Returns:**

- `latestBlock`: The latest block object.

### 7. `getNonce(provider: Provider, address: string)`

Retrieves the nonce for the default account.

**Parameters:**

- `provider`: An instance of ethers provider.
- `address`: The address to check the balance of (default is the default account).

**Returns:**

- `nonce`: The nonce for the default account.

### 8. `addressValid(address: string):`

Checks if an address is valid.

**Parameters:**

- `address`: The address to be validated.

**Returns:**

- `valid`: Boolean indicating if the address is valid.

### 9. `getEoa(accountPrivateKey: string)`

Generates an externally owned account (EOA) from a private key.

**Parameters:**

- `accountPrivateKey`: The private key of the account.

**Returns:**

- `eoa`: The generated EOA.

### 10. `transferNative(provider: Provider, wallet: Wallet, recipientAddress: string, amountToTransferInWei: BigInt, nativeGasUnit: number)`

Transfers native cryptocurrency from the default account to a recipient address.

**Parameters:**

- `provider`: An instance of ethers provider.
- `wallet`: an ether wallet to sign the ether transaction.
- `recipientAddress`: The address of the recipient.
- `amountToTransferInWei`: The amount of Ether to transfer.
- `nativeGasUnit`: The gas limit for the transaction.

**Returns:**

- `tx_receipt`: The transaction receipt.

### 11. `validateGasEstimation(provider: Provider, tx: TransactionRequest)`

Validates the gas estimation for a transaction.

**Parameters:**

- `provider`: An instance of ethers provider.
- `tx`: The transaction object.

### 12. isGasEstimationValid(provider: Provider, tx: TransactionRequest)`

Checks if the provided gas units are sufficient for the transaction.

**Parameters:**

- `provider`: An instance of ethers provider.
- `tx`: The transaction object.

**Returns:**

- `valid`: Boolean indicating if the gas units are sufficient.
- `gas_estimate`: The estimated gas units.

### 13. `decryptUint(ciphertext: bigint, userKey: string)`

Decrypts a value stored in a contract using a user key.

**Parameters:**

- `ciphertext`: The value to be decrypted.
- `userKey`: The user's AES key.

**Returns:**

- `result`: The decrypted value.

### 14. `decryptString(ciphertext: Array<bigint>, userKey: string)`

Decrypts a value stored in a contract using a user key.

**Parameters:**

- `ciphertext`: The value to be decrypted.
- `userKey`: The user's AES key.

**Returns:**

- `result`: The decrypted value.

### 15.`isProviderConnected(provider: Provider)`

Checks if the Web3 instance is connected.

**Parameters:**

- `provider`: An instance of ethers provider.

**Returns:**

- `connected`: Boolean indicating if Web3 is connected.

### 16. `getNativeBalance(address: string, provider: Provider)`

Retrieves the native balance of an address in Ether.

**Parameters:**

- `provider`: An instance of ethers provider.
- `address`: The address to check the balance of (default is the default account).

**Returns:**

- `result`: The address balance in Ether.

#### To report issues, please create a [github issue](https://github.com/coti-io/coti-sdk-typescript/issues)
