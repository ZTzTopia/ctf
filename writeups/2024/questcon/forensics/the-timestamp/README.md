---
title: "The Timestamp"
category: Forensics
tags: 
draft: false
completedDuringEvent: true
submitted: true
flag: QUESTCON{2023-01-17_09:30:45}
---
## Scenario

> Scenario:
>
> The Professor and his crew have pulled off their biggest heist yet, but the police are hot on their trail. During their digital forensics investigation, the authorities have stumbled upon a critical file, malware.exe, on a suspect's computer. The timestamps on the file could reveal key details about the heist timeline, but it seems that the crew has altered them to cover their tracks!
>
> The investigators suspect that Berlin, the mastermind behind the digital side of the operation, used a tool called Timestomp to manipulate the timestamps and throw the authorities off their trail. But with the right tools, you, as a digital forensics expert, can uncover the truth.
> 
> The $MFT (Master File Table) has been exported from the system, and the police have analyzed it using the AnalyzeMFT tool. Now it’s up to you to figure out whether Berlin tampered with the file's timestamps and uncover the real modification time of the file.
> 
> `Flag:  QUESTCON{YYYY-MM-DD_HH:MM:SS}`

## Solution

The challenge provides a file named `analyze_mft_output.txt` and a file named `malware_mft.json`. The `analyze_mft_output.txt` file contains the output of the `AnalyzeMFT` tool and the `malware_mft.json` file contains the metadata of the `malware.exe` file.

The `analyze_mft_output.txt` file contains two `Modified` timestamps. The first `Modified` timestamp is `2023-01-15 12:00:00` and the second `Modified` timestamp is `2023-01-17 09:30:45`. The second `Modified` timestamp represents the actual modification time of the file. This is because the first timestamp might be related to metadata changes or other non-content modifications, whereas the second timestamp reflects the true content modification time. We can extract the real modification time of the file from the `analyze_mft_output.txt` file.
