export const ONBOARD_CONTRACT_ADDRESS = "0x9E6987C8fD552d90c252B7fe4aF2387D47f928AE"
export const ONBOARD_CONTRACT_ABI = [
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "_from",
        type: "address",
      },
      {
        indexed: false,
        internalType: "bytes",
        name: "userKey",
        type: "bytes",
      },
    ],
    name: "AccountOnboarded",
    type: "event",
  },
  {
    inputs: [
      {
        internalType: "bytes",
        name: "signedEK",
        type: "bytes",
      },
      {
        internalType: "bytes",
        name: "signature",
        type: "bytes",
      },
    ],
    name: "OnboardAccount",
    outputs: [
      {
        internalType: "bytes",
        name: "accountKey",
        type: "bytes",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
]
