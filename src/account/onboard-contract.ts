export const ONBOARD_CONTRACT_ADDRESS = "0x60eA13A5f263f77f7a2832cfEeF1729B1688477c"
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
                "name": "userKey1",
                "type": "bytes"
            },
            {
                "indexed": false,
                "internalType": "bytes",
                "name": "userKey2",
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
