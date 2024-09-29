import { ethers, JsonRpcProvider } from "ethers"
import {
    printNetworkDetails,
    printAccountDetails,
    getAccountBalance,
    initEtherProvider,
    validateAddress,
    getLatestBlock,
    getNonce,
    addressValid,
    getNativeBalance,
    getEoa,
    transferNative,
    validateGasEstimation,
    isGasEstimationValid,
    isProviderConnected,
} from './../src'

jest.mock('ethers', () => ({
    ...jest.requireActual('ethers'),
    JsonRpcProvider: jest.fn(),
    Wallet: jest.fn().mockImplementation(() => ({
        address: '0x1234567890123456789012345678901234567890',
        getNonce: jest.fn().mockResolvedValue(0),
        sendTransaction: jest.fn().mockResolvedValue({
            hash: '0xTransactionHash',
            wait: jest.fn().mockResolvedValue(true),
        }),
    })),
    formatEther: jest.fn().mockImplementation((wei) => (wei / 1e18).toString()),
    isAddress: jest.fn().mockReturnValue(true),
    getAddress: jest.fn().mockReturnValue('0x1234567890123456789012345678901234567890'),
}))

describe('Your Module Tests', () => {
    let provider: any

    beforeEach(() => {
        provider = {
            getNetwork: jest.fn().mockResolvedValue({ chainId: 1 }),
            getBalance: jest.fn().mockResolvedValue(BigInt('1000000000000000000')), // 1 ETH
            getBlockNumber: jest.fn().mockResolvedValue(12345),
            getTransactionCount: jest.fn().mockResolvedValue(1),
            estimateGas: jest.fn().mockResolvedValue(BigInt(21000)),
            getFeeData: jest.fn().mockResolvedValue({ gasPrice: BigInt(1) }),
            broadcastTransaction: jest.fn().mockResolvedValue({})
        }
    })

    test('printNetworkDetails - should print network details', async () => {
        const consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {})

        await printNetworkDetails(provider)

        expect(consoleSpy).toHaveBeenCalledWith('chainId: 1')
        expect(consoleSpy).toHaveBeenCalledWith('latest block: 12345')

        consoleSpy.mockRestore()
    })

    test('printAccountDetails - should print account details', async () => {
        const consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {})

        await printAccountDetails(provider, '0x1234567890123456789012345678901234567890')

        expect(consoleSpy).toHaveBeenCalledWith('account address:', '0x1234567890123456789012345678901234567890')
        expect(consoleSpy).toHaveBeenCalledWith('account balance: ', BigInt('1000000000000000000'), 'wei (', '1.0', 'ether)')
        expect(consoleSpy).toHaveBeenCalledWith('account nonce: ', 1)

        consoleSpy.mockRestore()
    })

    test('getAccountBalance - should return account balance', async () => {
        const balance = await getAccountBalance('0x1234567890123456789012345678901234567890', provider)

        expect(balance).toEqual(BigInt('1000000000000000000'))
    })

    test('initEtherProvider - should return a new JsonRpcProvider instance', () => {
        const rpcUrl = 'https://example.com/rpc'
        const providerInstance = initEtherProvider(rpcUrl)

        expect(providerInstance).toBeInstanceOf(JsonRpcProvider)
        expect(JsonRpcProvider).toHaveBeenCalledWith(rpcUrl)
    })

    test('validateAddress - should validate address', () => {
        const result = validateAddress('0x1234567890123456789012345678901234567890')

        expect(result.valid).toBe(true)
        expect(result.safe).toBe('0x1234567890123456789012345678901234567890')
    })

    test('getLatestBlock - should return the latest block number', async () => {
        const latestBlock = await getLatestBlock(provider)

        expect(latestBlock).toBe(12345)
    })

    test('getNonce - should return the transaction count (nonce)', async () => {
        const nonce = await getNonce(provider, '0x1234567890123456789012345678901234567890')

        expect(nonce).toBe(1)
    })

    test('addressValid - should return true for a valid address', () => {
        const valid = addressValid('0x1234567890123456789012345678901234567890')

        expect(valid).toBe(true)
    })

    test('getNativeBalance - should return the native balance in ether', async () => {
        const balance = await getNativeBalance(provider, '0x1234567890123456789012345678901234567890')

        expect(balance).toBe('1.0')
    })

    test('getEoa - should return the address derived from the private key', async () => {
        const address = await getEoa('0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef')

        expect(address).toBe('0x1234567890123456789012345678901234567890')
    })

    test('transferNative - should successfully transfer native currency', async () => {
        const wallet = new ethers.Wallet('0x526c9f9fe2fc41fb30fd0dbba1d4d76d774030166ef9f819b361046f5a5b4a34', provider);
    
        const mockTransaction = {
            hash: '0xTransactionHash',
            wait: jest.fn().mockResolvedValue(true), // Mocking the wait function
        };

        // Mock sendTransaction to return the mockTransaction
        wallet.sendTransaction = jest.fn().mockResolvedValue(mockTransaction);

        const transaction = await transferNative(
            provider,
            wallet,
            '0x0987654321098765432109876543210987654321',
            BigInt('1000000000000000000'),
            21000
        );

        if (!transaction) {
            expect(false).toEqual(true)
            return
        }

        expect(transaction.hash).toBe('0xTransactionHash');
        expect(transaction.wait).toHaveBeenCalled(); // Ensure wait was called
    })

    test('validateGasEstimation - should throw error if gas estimation is invalid', async () => {
        const tx = { gasLimit: 20000 }
        jest.spyOn(provider, 'estimateGas').mockResolvedValue(BigInt(30000))

        await expect(validateGasEstimation(provider, tx)).rejects.toThrow('Not enough gas for tx. Provided: 20000, needed: 30000')
    })

    test('isGasEstimationValid - should return true for valid gas estimation', async () => {
        const tx = { gasLimit: 21000 }

        const result = await isGasEstimationValid(provider, tx)

        expect(result.valid).toBe(true)
        expect(result.gasEstimation).toEqual(BigInt(21000))
    })

    test('isProviderConnected - should return true if provider is connected', async () => {
        const isConnected = await isProviderConnected(provider)

        expect(isConnected).toBe(true)
    })
})