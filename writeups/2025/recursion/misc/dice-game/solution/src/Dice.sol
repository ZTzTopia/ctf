// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

contract Dice {
    struct Game {
        bytes32 clientSeed;
        bytes32[] serverSeedChain;
        uint32 remainingRolls;
    }

    mapping(address => Game) public games;

    function getGameHash(bytes32 serverSeed, bytes32 clientSeed) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(serverSeed, clientSeed));
    }

    function getNumberFromHash(bytes32 gameHash) public pure returns (uint256) {
        return uint256(gameHash) & 0xFFFFFFFFFFFFF;
    }

    function getRoll(bytes32 gameHash) public pure returns (uint256) {
        uint256 seed = getNumberFromHash(gameHash);
        return (seed % 1000) + 1;
    }

    function initialSeed(uint256 offset) public view returns (bytes32) {
        return keccak256(abi.encodePacked(block.timestamp + offset, msg.sender));
    }

    function startGame() public {
        require(games[msg.sender].remainingRolls <= 1, "Game already in progress");

        bytes32 clientSeed = initialSeed(block.number);
        bytes32[] memory serverSeedChain = new bytes32[](128);
        serverSeedChain[0] =
            keccak256(abi.encodePacked(initialSeed(block.number + 1)));

        for (uint32 i = 1; i < 128; i++) {
            serverSeedChain[i] = keccak256(abi.encodePacked(serverSeedChain[i - 1]));
        }

        games[msg.sender] = Game(clientSeed, serverSeedChain, 127);
    }

    function stopGame() public {
        require(games[msg.sender].remainingRolls > 0, "No game in progress");
        delete games[msg.sender];
    }

    function setClientSeed(bytes32 newClientSeed) public {
        require(games[msg.sender].remainingRolls > 0, "No game in progress");
        games[msg.sender].clientSeed = newClientSeed;
    }

    function rollDice(uint16 rollOver) public payable {
        require(msg.value > 0 && msg.value <= 100 ether, "Wager must be between 0 and 100 ETH");
        require(rollOver > 0 && rollOver <= 1000, "Roll over must be between 1 and 1000");

        Game storage game = games[msg.sender];
        require(game.remainingRolls > 0, "No rolls remaining");

        uint32 index = game.remainingRolls;
        bytes32 gameHash = getGameHash(game.serverSeedChain[index], game.clientSeed);
        uint256 roll = getRoll(gameHash);

        uint256 payout = 0;
        if (roll >= rollOver) {
            payout = msg.value * (102 / (101 - (rollOver / 10)));
            require(address(this).balance >= payout, "Contract has insufficient funds");
            payable(msg.sender).transfer(payout);
        }

        game.remainingRolls--;
    }

    function getRollsLeft() public view returns (uint32) {
        return games[msg.sender].remainingRolls;
    }

    function deposit() external payable {}
    receive() external payable {}
}
