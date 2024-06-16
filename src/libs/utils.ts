import {Contract, ethers, Interface, JsonRpcProvider, Provider, Transaction} from "ethers";
import fs from "fs";
import path from "path";
import type {TransactionRequest} from "ethers/src.ts/providers/provider";

export async function getNativeBalance(web3Provider: Provider, address: string) {
    return await web3Provider.getBalance(address);
}

export async function addressValid(address: string): Promise<boolean> {
    const result = await validateAddress(address);
    return result.valid;
}

export async function validateAddress(address: string): Promise<{valid: boolean, safe: string}> {
    return {'valid' : ethers.isAddress(address), 'safe': "yes"}
}

export function loadContracts(deploymentsDir: string) {
    const deployedContracts: Record<string, Contract> = {}
    const files = fs.readdirSync(deploymentsDir)

    files.map((f) => {
        const { address, abi } = JSON.parse(fs.readFileSync(path.join(deploymentsDir, f), "utf-8"))
        deployedContracts[f.replace(".json", "")] = new Contract(address, Interface.from(JSON.stringify(abi)))
    })

    return deployedContracts;
}

export async function web3Connected(web3Provider: Provider) {
    try {
        await web3Provider.getBlockNumber();
        console.log("Provider is connected.");
        return true;
    } catch (error) {
        console.error("Provider is not connected:", error);
        return false;
    }
}


export async function printNetworkDetails(web3Provider: Provider) {
    console.log(`provider + ${(await web3Provider.getNetwork()).chainId}`)
    console.log(`latest block: + ${await web3Provider.getBlockNumber()}`)

}

export function transferNative(web3Provider: Provider, fromAddress: string,  toAddress: string, privateKey: string, amount: number, gasLimit: number) {
    const transaction: TransactionRequest = {
        'to': toAddress,
        'from': fromAddress,
        'value': web3Provider.to_wei(amount_to_transfer_ether, 'ether'),
        'nonce': get_nonce(web3),
        'gasLimit': gasLimit,
        'gasPrice': web3Provider.eth.gas_price,
        'chainId': await web3Provider.getNetwork()).chainId
    }
    web3Provider.sendTransaction({

    })
}

export function initWeb3(rpcUrl: string) {
    return new JsonRpcProvider(rpcUrl)
}

export async function getNonce(web3Provider: Provider, account: string) {
    return web3Provider.getTransactionCount(account);
}

export async