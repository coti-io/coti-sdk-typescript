[![image](https://img.shields.io/badge/Telegram-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)](https://telegram.coti.io)
[![image](https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.coti.io)
[![image](https://img.shields.io/badge/X-000000?style=for-the-badge&logo=x&logoColor=white)](https://twitter.coti.io)
[![image](https://img.shields.io/badge/YouTube-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://youtube.coti.io)
[![COTI Website](https://img.shields.io/badge/COTI%20WEBSITE-4CAF50?style=for-the-badge)](https://coti.io)

# COTI TypeScript SDK

[![npm version](https://img.shields.io/npm/v/@coti-io/coti-sdk-typescript.svg)](https://www.npmjs.com/package/@coti-io/coti-sdk-typescript)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.20.5-brightgreen.svg)](https://nodejs.org/)

A powerful TypeScript SDK for building privacy-preserving applications on the COTI blockchain. Encrypt sensitive transaction inputs before submitting them to smart contracts, and decrypt encrypted data retrieved from the blockchain.

## 🎯 What is This SDK?

The COTI TypeScript SDK enables **privacy-preserving transactions** on the COTI blockchain by providing cryptographic utilities to:

- **Encrypt transaction inputs** before sending them to smart contracts
- **Decrypt encrypted data** retrieved from the blockchain
- **Generate cryptographic signatures** for contract verification
- **Support multiple data types**: unsigned integers (128-bit and 256-bit) and strings

This SDK is essential for applications that need to protect sensitive data while leveraging COTI's privacy features, including garbled circuits and on-chain compute capabilities.

## 🚀 Why Do You Need This SDK?

### Privacy-Preserving Transactions
Protect sensitive transaction data (amounts, user IDs, personal information) from being publicly visible on the blockchain while still maintaining verifiability through cryptographic signatures.

### Smart Contract Integration
Seamlessly prepare encrypted input text (`itUint`, `itUint256`, `itString`) that matches the expected format of COTI smart contracts, making integration straightforward.

### Type Safety
Full TypeScript support with comprehensive type definitions for all encrypted data structures, ensuring compile-time safety and better developer experience.


## 📦 Installation

```bash
npm install @coti-io/coti-sdk-typescript
```

### Requirements

- Node.js >= 18.20.5
- TypeScript (for TypeScript projects)

## 🔧 Quick Start

### Basic Usage

```typescript
import { Wallet } from 'ethers'
import { prepareIT, decryptUint } from '@coti-io/coti-sdk-typescript'

// Create a wallet and user key
const wallet = new Wallet('0x...') // Your private key
const userKey = '12345678901234567890123456789012' // 32-character hex string (AES key)

// Prepare encrypted input text for a 128-bit unsigned integer
const plaintext = 12345n
const contractAddress = '0x...' // Your smart contract address
const functionSelector = '0xa9059cbb' // Function selector (first 4 bytes of function signature hash)

const { ciphertext, signature } = prepareIT(
  plaintext,
  { wallet, userKey },
  contractAddress,
  functionSelector
)

// Submit ciphertext and signature to your smart contract
// ...

// Later, decrypt the data
const decrypted = decryptUint(ciphertext, userKey)
console.log(decrypted) // 12345n
```

### Working with 256-bit Integers

```typescript
import { prepareIT256, decryptUint256 } from '@coti-io/coti-sdk-typescript'

// For values larger than 128 bits, use prepareIT256
const largeValue = 2n ** 200n

const { ciphertext, signature } = prepareIT256(
  largeValue,
  { wallet, userKey },
  contractAddress,
  functionSelector
)

// Decrypt
const decrypted = decryptUint256(ciphertext, userKey)
```

### Working with Strings

```typescript
import { buildStringInputText, decryptString } from '@coti-io/coti-sdk-typescript'

const message = 'Hello, COTI!'

const { ciphertext, signature } = buildStringInputText(
  message,
  { wallet, userKey },
  contractAddress,
  functionSelector
)

// Decrypt
const decrypted = decryptString(ciphertext, userKey)
console.log(decrypted) // 'Hello, COTI!'
```

## 📚 Core Features

### Data Type Support

| Type | Function | Max Size | Use Case |
|------|----------|----------|----------|
| `uint128` | `prepareIT` / `decryptUint` | 128 bits | Standard integers, amounts, IDs |
| `uint256` | `prepareIT256` / `decryptUint256` | 256 bits | Large numbers, hashes, timestamps |
| `string` | `buildStringInputText` / `decryptString` | Unlimited | Messages, metadata, JSON data |

### Key Functions

#### Encryption Functions
- **`prepareIT(plaintext, sender, contractAddress, functionSelector)`** - Encrypts a 128-bit unsigned integer
- **`prepareIT256(plaintext, sender, contractAddress, functionSelector)`** - Encrypts a 256-bit unsigned integer
- **`buildStringInputText(plaintext, sender, contractAddress, functionSelector)`** - Encrypts a string

#### Decryption Functions
- **`decryptUint(ciphertext, userKey)`** - Decrypts a 128-bit unsigned integer
- **`decryptUint256(ciphertext, userKey)`** - Decrypts a 256-bit unsigned integer
- **`decryptString(ciphertext, userKey)`** - Decrypts a string

#### Cryptographic Utilities
- **`encrypt(key, plaintext)`** - Low-level AES encryption
- **`decrypt(key, r, ciphertext, r2?, ciphertext2?)`** - Low-level AES decryption
- **`sign(message, privateKey)`** - Sign arbitrary messages
- **`generateRSAKeyPair()`** - Generate RSA key pairs
- **`recoverUserKey(privateKey, encryptedKeyShare0, encryptedKeyShare1)`** - Recover AES key from encrypted shares

## 🔐 Security Considerations

- **User Key Management**: The `userKey` (AES key) must be kept secure. It's used for both encryption and decryption.
- **Private Key Security**: Never expose your wallet's private key. Use environment variables or secure key management systems.
- **Function Selectors**: Use the correct function selector for your smart contract function to ensure signature verification works correctly.
- **Key Generation**: Generate strong, random keys for production use. Never use hardcoded keys in production.

## 📖 API Documentation

Full API documentation with detailed examples is available in the [COTI Documentation](https://docs.coti.io/coti-v2-documentation/build-on-coti/tools/typescript-sdk).

## 🛠️ Development

### Building the SDK

```bash
npm install
npm run build
```

This compiles TypeScript to JavaScript in the `dist/` directory.

### Running Tests

The SDK includes comprehensive test coverage with 212+ tests:

```bash
# Run all tests
npm test

# Run specific test suites
npm test -- tests/unit
npm test -- tests/integration
```

#### Test Setup

Tests require a `.env` file with the following variables:

```env
TEST_PRIVATE_KEY=0x...  # Private key for wallet operations
TEST_USER_KEY=...       # 32-character hex string (AES key)
```

See `example.env` for reference.

### Project Structure

```
coti-sdk-typescript/
├── src/              # Source TypeScript files
│   ├── crypto_utils.ts  # Core cryptographic functions
│   ├── types.ts         # TypeScript type definitions
│   └── index.ts         # Main entry point
├── dist/             # Compiled JavaScript (generated)
├── tests/            # Test files
│   ├── unit/         # Unit tests
│   └── integration/  # Integration tests
└── package.json
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details on:

- Code of Conduct
- Development workflow
- Coding standards
- How to submit pull requests

## 📄 License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

## 🔗 Resources

- **Documentation**: [COTI Docs](https://docs.coti.io/coti-v2-documentation/build-on-coti/tools/typescript-sdk)
- **Website**: [COTI.io](https://coti.io)
- **Telegram**: [@coti_io](https://telegram.coti.io)
- **Discord**: [COTI Community](https://discord.coti.io)
- **Twitter**: [@COTInetwork](https://twitter.coti.io)

## 🐛 Reporting Issues

Found a bug or have a feature request? Please [open an issue](https://github.com/coti-io/coti-sdk-typescript/issues/new) on GitHub.

---


