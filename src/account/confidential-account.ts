import {BaseWallet, Contract, Provider, Wallet} from "ethers"
import {buildInputText} from "../crypto_utils"
import {onboard} from "./onboard"
import {decryptUint, initEtherProvider} from "../ethers_utils";

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

    public encryptValue(plaintextValue: bigint | number, contractAddress: string, functionSelector: string) {
        return buildInputText(BigInt(plaintextValue), this, contractAddress, functionSelector)
    }
}
