import { BaseWallet, Wallet, Contract, Provider } from "ethers"
import { decryptString, decryptUint, prepareStringIT, prepareUintIT } from "../libs/crypto"
import { getDefaultProvider } from "../provider"
import { onboard } from "./onboard"

export class ConfidentialAccount {
  constructor(readonly wallet: BaseWallet, readonly userKey: string) {}

  public decryptValue(ciphertextValue: bigint) {
    return decryptUint(ciphertextValue, this.userKey)
  }

  public encryptValue(plaintextValue: bigint | number, contractAddress: string, functionSelector: string) {
    return prepareUintIT(BigInt(plaintextValue), this, contractAddress, functionSelector)
  }

  public static async onboard(wallet: BaseWallet, contract?: Contract): Promise<ConfidentialAccount> {
    const userKey = await onboard(wallet, contract)
    return new ConfidentialAccount(wallet, userKey)
  }

  public static createWallet(provider?: Provider): BaseWallet {
    return Wallet.createRandom(provider ?? getDefaultProvider())
  }
}
