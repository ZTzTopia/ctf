---
title: IndustrialChain
categories: Blockchain
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 30
solves: -1
flag: THM{REDACTED}
---
> Flicker has ghosted through your decentralised control logic quietly, reversing override conditions in your smart contract. The main switch appears engaged, but safety locks remain enforced at the contract level.
>
> Your mission: Reclaim manual control. Could you review the smart contract logic and execute the correct sequence to override the sabotage?

---

The challenge presents a Solidity smart contract that simulates a decentralized control system with multiple operational states. The goal is to transition the system into a fully active state by invoking the correct sequence of function calls.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Challenge {
    bool public emergencyShutdown = false;
    bool public systemActivated = false;
    bool public you_solved_it = false;
    address public operator;

    constructor() {
        operator = msg.sender;
    }

    function engageMainSwitch() external  returns (bool) {
        systemActivated = true;
        return true;
    }

    function pressOverrideButton() external  returns (bool) {
        require(systemActivated, "System not activated");
        you_solved_it = true;
        return true;
    }

    function isSolved() external view returns (bool) {
        return you_solved_it;
    }

    function checkSystem() external view returns (string memory) {
        if (you_solved_it) {
            return "System Online  Mission Accomplished!";
        } else if (systemActivated) {
            return "System Activated  Awaiting Override...";
        } else {
            return "System Offline Engage Main Switch";
        }
    }
}
```

```solidity
function engageMainSwitch() external returns (bool) {
    systemActivated = true;
    return true;
}
```

This function mimics turning on the main power. It sets `systemActivated` to `true`. This step is mandatory before attempting the override.

```solidity
function pressOverrideButton() external returns (bool) {
    require(systemActivated, "System not activated");
    you_solved_it = true;
    return true;
}
```

This function is the override mechanism. It checks if the system has already been activated (`systemActivated == true`). If not, it throws an error. Once passed, it marks the system as solved.

```sh
cast call --rpc-url <rpc-url> <contract-address> "checkSystem()"
```

This confirms the initial state, likely returning: `"System Offline Engage Main Switch"`

```sh
cast send --private-key <private-key> --rpc-url <rpc-url> --legacy <contract-address> "engageMainSwitch()"
```

This activates the system, changing `systemActivated` to `true`.

```sh
cast send --private-key <private-key> --rpc-url <rpc-url> --legacy <contract-address> "pressOverrideButton()"
```

This executes the override, setting `you_solved_it` to `true`.
