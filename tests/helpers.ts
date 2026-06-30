import { Wallet } from 'ethers'

export const TEST_CONSTANTS = {
    PRIVATE_KEY: '0x59c6995e998f97a5a0044966f09453840b0d2e8b9c6db82a09288f89c37c7912',
    USER_KEY: '0123456789abcdef0123456789abcdef',
    CONTRACT_ADDRESS: '0x0000000000000000000000000000000000000001',
    FUNCTION_SELECTOR: '0x11223344'
}

export function createTestSender() {
    return {
        wallet: new Wallet(TEST_CONSTANTS.PRIVATE_KEY),
        userKey: TEST_CONSTANTS.USER_KEY
    }
}
