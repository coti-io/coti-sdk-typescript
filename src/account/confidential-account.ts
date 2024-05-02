import { BaseWallet, Wallet, Contract, Provider, JsonRpcProvider } from "ethers"
import { decryptValue, prepareIT } from "../libs/crypto"
import { onboard } from "./onboard"

function getDefaultProvider() {
  return new JsonRpcProvider("https://devnet.coti.io")
}

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

  public static createWallet(provider?: Provider): BaseWallet {
    return Wallet.createRandom(provider ?? getDefaultProvider())
  }
}
