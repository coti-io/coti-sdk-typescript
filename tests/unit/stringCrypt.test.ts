import { ethers } from "ethers";
import { 
    buildStringInputText, 
    decryptString, 
    generateRandomAesKeyBinaryString 
} from "../../src/crypto_utils";

describe("String Encryption and Decryption (decryptString)", () => {
    let wallet: ethers.BaseWallet;
    let userKey: string;
    let sender: { wallet: ethers.BaseWallet; userKey: string };
    const contractAddress = "0x0000000000000000000000000000000000000000";
    const functionSelector = "0x12345678";

    beforeAll(() => {
        wallet = ethers.Wallet.createRandom();
        // generateRandomAesKeyBinaryString() returns 16 raw bytes (a forge binary string).
        // The SDK's documented AES key format is 32 hex chars, so convert it.
        userKey = Buffer.from(generateRandomAesKeyBinaryString(), "binary").toString("hex");
        sender = { wallet, userKey };
    });

    it("should correctly encrypt and decrypt an empty string", () => {
        const it = buildStringInputText("", sender, contractAddress, functionSelector);
        expect(it.ciphertext.value).toEqual([]);
        expect(decryptString(it.ciphertext, userKey)).toBe("");
    });

    it("should correctly encrypt and decrypt unicode and emoji content", () => {
        const targetString = "Hello 世界 🌍";
        const it = buildStringInputText(targetString, sender, contractAddress, functionSelector);
        expect(decryptString(it.ciphertext, userKey)).toBe(targetString);
    });

    it("should handle a string spanning three 8-byte chunks", () => {
        const targetString = "a".repeat(17); // 17 bytes => 3 chunks
        const it = buildStringInputText(targetString, sender, contractAddress, functionSelector);
        expect(it.ciphertext.value.length).toBe(3);
        expect(decryptString(it.ciphertext, userKey)).toBe(targetString);
    });

    it("should correctly encrypt and decrypt a string perfectly matching the 8-byte chunk size", () => {
        const targetString = "12345678"; // Exact 8 bytes
        const it = buildStringInputText(targetString, sender, contractAddress, functionSelector);
        
        const decrypted = decryptString(it.ciphertext, userKey);
        expect(decrypted).toBe(targetString);
    });

    it("should correctly encrypt and decrypt a string with padding (less than 8 bytes)", () => {
        const targetString = "Hello"; // 5 bytes => pads 3 bytes
        const it = buildStringInputText(targetString, sender, contractAddress, functionSelector);
        
        const decrypted = decryptString(it.ciphertext, userKey);
        expect(decrypted).toBe(targetString);
        expect(decrypted.length).toBe(targetString.length); // Verifies trailing null bytes are gone
    });

    it("should correctly encrypt and decrypt a multi-chunk string with padding", () => {
        const targetString = "Hello World!"; // 12 bytes => 1 chunk (8) + 1 chunk (4 + pads 4)
        const it = buildStringInputText(targetString, sender, contractAddress, functionSelector);
        
        // Assert there are 2 chunks under the hood
        expect(it.ciphertext.value.length).toBe(2); 

        const decrypted = decryptString(it.ciphertext, userKey);
        expect(decrypted).toBe(targetString);
    });

    it("should preserve strings with null-like characters strictly intentionally inside the string", () => {
        const targetString = "a\0b\0c"; // Internal null characters
        const it = buildStringInputText(targetString, sender, contractAddress, functionSelector);
        
        const decrypted = decryptString(it.ciphertext, userKey);
        expect(decrypted).toBe(targetString);
    });
});
