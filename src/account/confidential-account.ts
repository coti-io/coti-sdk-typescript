import {BaseWallet, Contract, Provider, Wallet} from "ethers"
import {buildInputText, buildStringInputText, decryptString, decryptUint} from "../crypto_utils"
import {onboard} from "./onboard"
import {initEtherProvider} from "../ethers_utils";

export class ConfidentialAccount {
    constructor(readonly wallet: BaseWallet, readonly userKey: string) {
    }

    public static async onboard(wallet: BaseWallet, contract?: Contract): Promise<ConfidentialAccount> {
        const userKey = await onboard(wallet, contract)
        return new ConfidentialAccount(wallet, userKey)
    }

    public static createWallet(provider?: Provider): BaseWallet {
        return Wallet.createRandom(provider ?? initEtherProvider())
    }

    public decryptValue(ciphertextValue: bigint) {
        return decryptUint(ciphertextValue, this.userKey)
    }

    public decryptString(ciphertextValue: bigint[]) {
        return decryptString(ciphertextValue, this.userKey)
    }

    public encryptUint(plaintextValue: bigint | number, contractAddress: string, functionSelector: string) {
        return buildInputText(BigInt(plaintextValue), this, contractAddress, functionSelector)
    }

    public encryptString(plaintextValue: string, contractAddress: string, functionSelector: string) {
        return buildStringInputText(plaintextValue, this, contractAddress, functionSelector)
    }
}
