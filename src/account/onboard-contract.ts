export const ONBOARD_CONTRACT_ADDRESS = "0x413370ed41FB9EE3aea0B1B91FD336cC0be1Bad6"
export const ONBOARD_CONTRACT_ABI = [
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "address",
        "name": "_from",
        "type": "address"
      },
      {
        "indexed": false,
        "internalType": "bytes",
        "name": "userKey",
        "type": "bytes"
      }
    ],
    "name": "AccountOnboarded",
    "type": "event"
  },
  {
    "inputs": [
      {
        "internalType": "bytes",
        "name": "publicKey",
        "type": "bytes"
      },
      {
        "internalType": "bytes",
        "name": "signedEK",
        "type": "bytes"
      }
    ],
    "name": "onboardAccount",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  }
]