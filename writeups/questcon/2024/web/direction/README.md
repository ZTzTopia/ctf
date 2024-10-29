---
title: Direction
category: "Web Exploitation"
tags: 
  - misdirection
  - robots.txt
draft: true
completedDuringEvent: true
submitted: true
flag: QUESTCON{mi3d1r3ct10n_15_4n_4r}
---
## Scenario

> Something seems off with the plan displayed on this site. Can you uncover what's hidden behind the scenes and find the way out? The Professor always has a trick up his sleeve.

## Solution

Visit the URL https://<url>/robots.txt to view the `robots.txt` file. The content of the file is:
```
User-agent: *
Disallow: /start
```

Despite the disallow directive, POST to https://<url>/start. This path will redirect you to another path, `/start` -> `/redirect0` -> `/redirect1` -> `/redirect2` -> `/redirect3` -> `/redirect4`.

You will see the part of the flag in the header `x-flag-part` of the response. The flag is split into 5 parts.
