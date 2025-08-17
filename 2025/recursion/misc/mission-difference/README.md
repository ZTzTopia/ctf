---
title: "Mission Difference"
category: Miscellaneous
tags: 
  - OSINT
draft: false
completedDuringEvent: true
submitted: true
flag: RECURSION{4h_i_th0ught_you_w4nt3d_t0_g1ve_m3_som3_ETH}
---
> I want to use **Mission Difference 674** name but it's already taken :(.
>
> Note: You need to log into the website you found.

by `ztz`

---

I started my investigation by searching for **MissionDifference674** on Google. This search quickly led me to a [Reddit profile](https://www.reddit.com/user/MissionDifference674/). While browsing the profile, I noticed a custom feed named "Programming" and observed that the user was a member of the "r/learncpp443" community.

Curious about this subreddit, I visited it and examined the list of moderators. By checking their profiles, I eventually found an email address in one of the moderator descriptions. I decided to reach out to the moderator via email, and in response, I received a hex string.

Upon inspection, I recognized the hex string as a blockchain address on the **Sepolia testnet** (`0xc13Fbc18a3a06C8C0521F8026714DbcD8a7e34c3`). I explored the transaction history of this address and discovered a smart contract transaction. In the constructor call of this contract, I found a string argument that turned out to be the flag.
