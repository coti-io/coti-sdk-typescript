import {ethers, JsonRpcProvider, Provider, toNumber, TransactionRequest, Wallet} from "ethers";

export async function printNetworkDetails(provider: Provider) {
    if (!await isProviderConnected(provider)) {
        throw Error("provider not connected");
    }
    if (provider instanceof ethers.JsonRpcProvider) {
        console.log(`provider: ${provider._getConnection().url}`)
    }
    const network = await provider.getNetwork();
    console.log(`chainId: ${network.chainId}`)
    console.log(`latest block: ${await getLatestBlock(provider)}`)
}

export async function printAccountDetails(provider: Provider, address: string) {
    if (!(await isProviderConnected(provider) && addressValid(address))) {
        throw Error("provider not connected or address is not valid address");
    }
    console.log("account address:", address);
    const balanceInWei = await getAccountBalance(address, provider)
    console.log("account balance: ", balanceInWei, 'wei (', ethers.formatEther(balanceInWei.toString()), 'ether)');
    console.log("account nonce: ", await getNonce(provider, address))
}

export async function getAccountBalance(address: string, provider: Provider) {
    if (!(await isProviderConnected(provider) && addressValid(address))) {
        throw Error("provider not connected or address is not valid address");
    }
    return provider.getBalance(address);
}

export function initEtherProvider(rpcUrl: string = "https://devnet.coti.io/rpc") {
    return new JsonRpcProvider(rpcUrl)
}

export function validateAddress(address: string): { valid: boolean; safe: string } {
    return {'valid': ethers.isAddress(address), 'safe': ethers.getAddress(address)}
}

export async function getLatestBlock(provider: Provider) {
    if (!await isProviderConnected(provider)) {
        throw Error("provider not connected or address is not valid address");
    }
    return await provider.getBlockNumber()
}

export async function getNonce(provider: Provider, address: string) {
    if (!(await isProviderConnected(provider) && addressValid(address))) {
        throw Error("provider not connected or address is not valid address");
    }
    return await provider.getTransactionCount(address)
}

export function addressValid(address: string): boolean {
    return validateAddress(address).valid
}

export async function getNativeBalance(provider: Provider, address: string) {
    if (!(await isProviderConnected(provider) && addressValid(address))) {
        throw Error("provider not connected or address is not valid address");
    }
    return ethers.formatEther(await getAccountBalance(address, provider))
}

export async function getEoa(accountPrivateKey: string) {
    const wallet = new Wallet(accountPrivateKey);
    if (!addressValid(wallet.address))
        throw new Error("Address generated from pk is not valid");
    return wallet.address;
}

export async function transferNative(provider: Provider, wallet: Wallet, recipientAddress: string, amountToTransferInWei: BigInt, nativeGasUnit: number) {
    const feeData = await provider.getFeeData();
    const gasPrice = feeData.gasPrice;

    const tx: TransactionRequest = {
        to: recipientAddress,
        from: wallet.address,
        value: amountToTransferInWei.toString(),
        nonce: await wallet.getNonce(),
        gasLimit: nativeGasUnit,
        gasPrice: gasPrice
    };
    try {
        await validateGasEstimation(provider, tx)
        const transaction = await wallet.sendTransaction(tx);
        await transaction.wait();

        console.log('Transaction successful with hash:', transaction.hash);
        return transaction;
    } catch (error) {
        console.error('Transaction failed:', error);
    }
}

export async function validateGasEstimation(provider: Provider, tx: TransactionRequest) {
    const {valid, gasEstimation} = await isGasEstimationValid(provider, tx);
    if (!valid)
        throw new Error(`Not enough gas for tx. Provided: ${tx.gasLimit}, needed: ${gasEstimation}`);
}

export async function isGasEstimationValid(provider: Provider, tx: TransactionRequest) {
    const estimatedGas = await provider.estimateGas(tx)
    const gasLimit = tx.gasLimit ? toNumber(tx.gasLimit) : 0;

    if (!estimatedGas || estimatedGas > gasLimit) {
        throw new Error(`Not enough gas for tx. Provided: ${gasLimit}, needed: ${estimatedGas.toString()}`);
    }
    return {valid: true, gasEstimation: estimatedGas}
}

export async function isProviderConnected(provider: Provider): Promise<boolean> {
    if (provider == undefined) {
        throw Error('Provider does not exist.')
    }
    const network = await provider.getNetwork();
    if (!network)
        return false
    return true
}