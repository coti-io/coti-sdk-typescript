export const ONBOARD_CONTRACT_ADDRESS = "0xadb3952a07B2c9fA7dbd2F583cd2F0412C97eC33"
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
