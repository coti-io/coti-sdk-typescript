export const ONBOARD_CONTRACT_ADDRESS = "0x5D49C3F49F19dc4e257975Fb1CcE057b3796f5F1"
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
        "name": "signedEK",
        "type": "bytes"
      },
      {
        "internalType": "bytes",
        "name": "signature",
        "type": "bytes"
      }
    ],
    "name": "OnboardAccount",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  }
]
