---
title: "The Murder of Alfred Cuthbert"
categories: Misc
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 107
solves: 21
flags: ITFest26{Oliver_Allion}
---

> POLICE REPORT:
>
> - Victim: Alfred Cuthbert (25y)
> - Crime Scene: Room 512, Crimson Red Apartment
> - Dead Body Found: Thursday, 23 July 2026 | 02:53 PM
> - Estimated Time of Death: Wednesday, 22 July 2026 | 04:21 PM
>
> CRIMSON RED APARTMENT SECURITY NOTICE:
>
> - Only the lobby camera was operational. Cameras installed on residential floors, including the 5th floor, were out of service due to an unresolved maintenance issue.
>
> INVESTIGATION NOTES:
>
> - Someone hired an assassin to commit the murder.
> - Find both the assassin and the person who hired them.
>
> FLAG FORMAT: ITFest26{AssassinName\_PersonWhoHired}
>
> Example:

> - Assassin: Caroline W
> - Person who Hired: Brandon C
> - Flag: ITFest26{Caroline\_Brandon}

Author: nuby

---

Given a remote about suspects. So, we can try all the options on the remote, and Oliver Scott got `delivery_history.pdf`.

```
---------------------------------------------------
| Name       | Receiver      | Status             |
---------------------------------------------------
| Ovnapn O   | Natryvan J     | Delivered          |
| Nyyvba O   | Nyserq P       | Delivered          |
| Uneevfba F | Byvivn C       | Ready to Deliver  |
| Znggurj O  | Wbuafba S      | Ready to Deliver  |
| Znex G     | Mrab Q         | Waiting Payment   |
---------------------------------------------------
```

It was already obvious from the start that it was suspicious, because if we investigated everything else, it was just a normal conversation, but why was Oliver Scott offering an anonymous chat?

So, i asked the AI ​​a few times, but it felt like a mistake (bro doubted his potential to read because of AI), the AI ​​got the names of Allion wrong. Here's an example of a session: <https://chatgpt.com/share/6a774e3b-d1bc-83ec-9398-7dde50c01ab6>. In the end, i tried brute-force, but it wasn't possible because it was a lot and i was too lazy.

So, i finally tried reading and decoding (rot-13) it myself, and it turned out it wasn't Allison, but Allion. So, the killer was Oliver Scott, and the one who ordered him was Allion.
