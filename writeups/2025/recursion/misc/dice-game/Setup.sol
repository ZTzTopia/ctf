// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { Dice } from "./Dice.sol";

contract Setup {
    Dice public dice;
    address public player;

    constructor(address _player) {
        dice = new Dice();
        player = _player;
    }

    function isSolved() public view returns (bool) {
        return player.balance > 1_337 ether;
    }

    function getChallengeAddress() public view returns (address) {
        return address(dice);
    }
}
