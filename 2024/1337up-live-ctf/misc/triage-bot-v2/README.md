---
title: "Triage Bot v2"
categories: Miscellaneous
tags: 
completedDuringEvent: true
submitted: true
flag: INTIGRITI{4n07h3r_y34r_4n07h3r_7r1463_b07}
draft: false
---
## Scenario

> Check out our new and improved Triage Bot!
>
> https://go.intigriti.com/discord

By 0xM4hm0ud & CryptoCat

## Solution

The challenge description mentions a Discord bot, so I joined the Discord server and found the bot in the `#🤖┃triage-bot` channel. 

The bot prefix was `!` and the help command was `!help`. The help command showed the available commands.

![image](image.png)

After checking all the commands, I found the interesting command `!news`. There is new command added in the bot `!read_report`. I tried to use the command `!read_report` but it was not working. The bot said that I need to be assigned the role `triage` to use the command.

![image-1](image-1.png)

So I invited the bot to my server and assigned the role `triage` to myself. After that, I used the command `!read_report 0` and the bot gave me the flag.

![image-2](image-2.png)
