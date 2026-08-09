---
title: "Kingdom of Catofel"
categories: Misc
tags:
draft: false
points: 102
solves: 26
flags: ITFest26{c0n9r4tul4t10n5}
---

> An elf, realizing your high potential, decided to lead you to a magic chest with the flag inside. But the chest, since it contains the most valuable treasure, needs a key which is as magical as the chest.
>
> But, to gain the key, a strange rule exists. Adventurer needs to visit places in the right order.
>
> Most adventurers failed because they didn't pay attention for the clues throughout the journey. But one day, a group led by Rubillion Charis found the clues and made the right order. Unfortunately, they died before reaching the chest. Something seemed to attack them while they were sleeping at the forest near a temple, and Rubillion's journal was found near her body.
>
> In order to acquire the magic key, the elf gave you some relics:
>
> - Adventurer's Handbook
> - Rubillion's Journal
> - These relics could help you to unlock the chest and claim the flag.
>
> Good luck, adventurers. Beware of the kaiju. Happy traveling!
>
> FLAG FORMAT: ITFest26{...}
>
> Author: nuby

---

We get three files: the two relics named in the description, and the chest itself, a password-protected `magic_chest.7z`.

Rubillion's journal.txt:

```
Day 17

After long days of journey, we finally made it close to this kingdom. Kingdom of Catofel. A kingdom that its name is written on more that 500+ ancient manuscripts. They said that this place holds such priceless treasure, and they call it "flag". We don't understand what does "flag" mean. Is it like a country flag? Or pirate flag? But we're so intended to find out. 

Day 18

We headed to the South Gate. Two guards standing in front of it with their big axe crossing each other, stopping us from walking in. 

"We are here to look for the legendary flag", I said as I handed them a permission letter. 

The guard read the letter, nodded, and opened the gate for us. We walked in.

Day 19 

The kingdom villagers were so nice. They gave us free inn to stay and rest. Today, we decided to go to a local library, called Imperial Library, to look for any clues about the location of the magic chest. We spent hours reading books, manuscripts, and journals. From them, we knew that the magic chest are located inside the kingdom's oldest temple, Temple of Edbris. We also got some information about a dark cave which is a kaiju's lair.

Day 20 

Today was our last day at this village before we decided to continue our journey. Some of us decided to stay at the inn to take a rest, while some of us went to a coffee shop that is known for its latte. 

Cato Coffee Shop's latte was no joke. It was probably the best latte I've ever tasted. The waiter welcomed and served us very nicely, even they gave us one free affogato.

"Special treats for every adventurers", they said. 

Day 21 

We packed our things and continue our journey. I know it will take days to reach the temple. I couldn't sleep so I decided to write journal. Others are sleeping. We found a good spot here in Lullaby Forest to spend the night. Like its name, Lullaby, this forest is so comfortable for resting, it's like our mother sing us a lullaby when we were child. 

Day 22 

-

Day 23

-

Day 24

We're close to the temple. Not long before, we almost put ourselves in danger. According to map, there was a shortcut, so we could reach the temple quicker. But then, we remembered something we read from the library. That shortcut also lead to a dark cave in which kaiju lairs, also called as Gloomy Cavern. So we immediately turned back and took a longer path to save our life. 

Day 25 

Finally, Temple of Edbris can be seen. But we decided to spend the night and rest first before coming to the temple. We're so excited, I can't sleep.

Day 26 

 
```

The Adventurer's Handbook is a table of twelve places in the kingdom, each with a code in the shape `CTFxxx`:

| No. | Name of the Place | Special Code |
| --- | --- | --- |
| 1. | Imperial Library | CTF065 |
| 2. | Gloomy Cavern | CTF070 |
| 3. | Moon Lake | CTF075 |
| 4. | Warren Wizard House | CTF079 |
| 5. | Cato Coffee Shop | CTF071 |
| 6. | Tulips Meadow | CTF081 |
| 7. | Royal Blacksmith | CTF078 |
| 8. | South Gate | CTF077 |
| 9. | Temple of Edbris | CTF067 |
| 10. | Goblin Village | CTF082 |
| 11. | Roseanne River | CTF088 |
| 12. | Lullaby Forest | CTF073 |

The description says the adventurer must visit places in the right order. The journal records it day by day. Day 18: through the South Gate. Day 19: the Imperial Library. Day 20: Cato Coffee Shop. Day 21: a night in Lullaby Forest. Day 25: the Temple of Edbris at last. On Day 24 they almost take the shortcut through Gloomy Cavern, the kaiju's lair, and turn back. Only the five places the party actually visited matter, and their codes line up like this in journey order:

| Place | Code | Letter |
| --- | --- | --- |
| South Gate | CTF077 | M |
| Imperial Library | CTF065 | A |
| Cato Coffee Shop | CTF071 | G |
| Lullaby Forest | CTF073 | I |
| Temple of Edbris | CTF067 | C |

Each code is `CTF` followed by three decimal digits, and those three digits are one ASCII code. `MAGIC` is that key, and it opens the archive. Inside is `flag.pdf`, which holds the flag.
