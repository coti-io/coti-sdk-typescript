import { BaseWallet, keccak256, Contract, Signer } from "ethers"
import { generateRSAKeyPair, decryptRSA, sign } from "../libs/crypto"
import { ONBOARD_CONTRACT_ADDRESS, ONBOARD_CONTRACT_ABI } from "./onboard-contract"

function getDefaultContract(wallet: Signer) {
  return new Contract(ONBOARD_CONTRACT_ADDRESS, JSON.stringify(ONBOARD_CONTRACT_ABI), wallet)
}

export async function onboard(user: BaseWallet, contract = getDefaultContract(user)) {
  const { publicKey, privateKey } = generateRSAKeyPair()

  const signedEK = sign(keccak256(publicKey), user.privateKey)
  const receipt = await (await contract.OnboardAccount(publicKey, signedEK, { gasLimit: 12000000 })).wait()
  if (!receipt || !receipt.logs || !receipt.logs[0]) {
    throw new Error("failed to onboard account")
  }
  const decodedLog = contract.interface.parseLog(receipt.logs[0])
  if (!decodedLog) {
    throw new Error("failed to onboard account")
  }
  const encryptedKey = decodedLog.args.userKey
  const buf = Buffer.from(encryptedKey.substring(2), "hex")
  return decryptRSA(privateKey, buf).toString("hex")
}
