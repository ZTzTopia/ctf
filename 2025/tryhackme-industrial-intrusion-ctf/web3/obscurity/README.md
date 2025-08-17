---
title: Obscurity
categories: Blockchain
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 60
solves: -1
flag: THM{REDACTED}
---
> The plant’s override relay was blockchain-governed. That is until **Flicker** embedded a sabotage handshake inside the contract’s state logic. Now, the machinery won’t respond unless the hidden sequence is re-executed.
>
> Sensors are reading “Main switch: ON”, but nothing moves. Flicker’s smart contract ghost fork rewired state verification, hiding the real override behind two calls in just the right order.

---

The challenge provides a Solidity smart contract that simulates a control system with a secret code to unlock the flag. The goal is to call the `unlock` function with the correct code to retrieve the flag.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Challenge {
    string private secret = "THM{}";
    bool private unlock_flag = false;
    uint256 private code;
    string private hint_text;
    
    constructor(string memory flag, string memory challenge_hint, uint256 challenge_code) {
        secret = flag;
        code = challenge_code;
        hint_text = challenge_hint;
    }
    
    function hint() external view returns (string memory) {
        return hint_text;
    }
    
    function unlock(uint256 input) external returns (bool) {
        if (input == code) {
            unlock_flag = true;
            return true;
        }
        return false;
    }
    
    function isSolved() external view returns (bool) {
        return unlock_flag;
    }
    
    function getFlag() external view returns (string memory) {
        require(unlock_flag, "Challenge not solved yet");
        return secret;
    }
}
```

The contract has a constructor that initializes the `secret`, `hint_text`, and `code` variables. The `hint` function returns a hint, and the `unlock` function checks if the input matches the stored code. If it does, it sets `unlock_flag` to `true`.

```solidity
string private secret = "THM{}";
bool private unlock_flag = false;
uint256 private code;
string private hint_text;
```

The contract has a private variable `code` that stores the secret code needed to unlock the flag. The `hint` function returns a hint, and the `unlock` function checks if the input matches the stored code.

We can interact with the contract using `storage` to retrieve the value of `code` and then call the `unlock` function with that value.

```sh
cast storage <contract-address>  2 --rpc-url <rpc-url>
```

The `cast storage` command retrieves the value of the `code` variable from the contract's storage. The output will be a hexadecimal representation of the code.

```sh
cast send --private-key <private-key>  --rpc-url <rpc-url> <contract-address>  --legacy "unlock(6778)"
```

This command sends a transaction to the contract's `unlock` function with the code obtained from the previous step. If the code is correct, it will set `unlock_flag` to `true`.
