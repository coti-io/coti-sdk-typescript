import { BaseWallet, Contract } from "ethers"
import { decryptValue, prepareIT } from "../libs/crypto"
import { onboard } from "./onboard"

export class ConfidentialAccount {
  constructor(readonly wallet: BaseWallet, readonly userKey: string) {}

  public decryptValue(ciphertextValue: bigint) {
    return decryptValue(ciphertextValue, this.userKey)
  }

  public encryptValue(plaintextValue: bigint | number, contractAddress: string, functionSelector: string) {
    return prepareIT(BigInt(plaintextValue), this, contractAddress, functionSelector)
  }

  public static async onboard(wallet: BaseWallet, contract?: Contract): Promise<ConfidentialAccount> {
    const userKey = await onboard(wallet, contract)
    return new ConfidentialAccount(wallet, userKey)
  }
}
