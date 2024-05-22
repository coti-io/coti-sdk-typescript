import { JsonRpcProvider } from "ethers"

export function getDefaultProvider() {
  return new JsonRpcProvider("https://devnet.coti.io/rpc")
}
