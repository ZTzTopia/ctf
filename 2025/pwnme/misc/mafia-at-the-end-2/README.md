---
title: "Mafia at the end 2"
categories: Miscellaneous
tags: Blockchain
draft: false
completedDuringEvent: true
submitted: true
flags: PWNME{th3_H0us3_41way5_w1n_bu7_sh0uld_be_4fr41d_0f_7h3_ul7im4te_g4m8l3r!}
---
> You're in the final step before catching them lacking. Prove yourself by winning at the casino and access the VIP room !
>
> But remember, the house always win.
>
> Note : To connect to the casino with Metamask, we recommend you to use another browser and a "trash" MetaMask wallet to avoid some weird behavior.
>
> Author : `Wefpen, Tzer`
>
> Flag format: `PWNME{.........................}`
>
> Connect : `nc mafia2.phreaks.fr 10020`

by Wefpen and Tzer

---

Given `Setup.sol` and `Casino.sol`, we can see that the casino contract uses a PRNG to determine the outcome of the game. The PRNG is seeded with the `prevrandao` value from the previous block. We can use this information to predict the outcome of the game.

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

contract CasinoPWNME {

  bool public isWinner;

	uint256 public multiplier = 14130161972673258133;
	uint256 public increment = 11367173177704995300;
	uint256 public modulus = 4701930664760306055;
  uint private state;

  constructor (){
    state = block.prevrandao % modulus;
  }

  function checkWin() public view returns (bool) {
    return isWinner;
  }

  function playCasino(uint number) public payable  {

    require(msg.value >= 0.1 ether, "My brother in christ, it's pay to lose not free to play !");
    PRNG();
    if (number == state){
      isWinner = true;
    } else {
      isWinner = false;
    }
  }
  
  function PRNG() private{
    state = (multiplier * state + increment) % modulus;
  }

}
```

So we can see the `state` is at storage slot `0x4`. We can get the value of the state by calling `web3.eth.getStorageAt(casinoAddress, "0x4")`. We can then calculate the next state by using the PRNG formula.

```sol
bool public isWinner;

uint256 public multiplier = 14130161972673258133;
uint256 public increment = 11367173177704995300;
uint256 public modulus = 4701930664760306055;
uint private state;
```

Here is the code to predict the outcome of the game:

```js
const stateStorage = await web3.eth.getStorageAt(casinoAddress, "0x4");
console.log("State:", BigInt(stateStorage).toString());

const multiplier = BigInt("14130161972673258133");
const increment = BigInt("11367173177704995300");
const modulus = BigInt("4701930664760306055");

let state = BigInt(stateStorage) % modulus;
state = (multiplier * state + increment) % modulus;
```

Note: The code above is write to the casino website source code. and modify `playCasino` arguments from `0` to `state` value. (The challenge start instance error, so we can't connect to the casino)
