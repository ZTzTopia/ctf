---
title: sus
categories: Reverse Engineering
tags: 
draft: false
completedDuringEvent: true
submitted: true
flag: bronco{br4inr0t}
---
> So, my friend just hit me up with this lit file, right? But like, they totally forgot to define their keywords\u2014straight up left me hanging. It\u2019s like I\u2019m playing a game of \"guess the meaning\" with no map. I gotta reverse the code and figure out what\u2019s actually poppin\u2019 in there. There\u2019s a flag hidden somewhere, but it\u2019s got mad twists and turns. If you\u2019re down to decode it too, try flipping the meaning of the words and see if you can catch the vibe. Let's see who can crack it first!

By serilical

---

The challenge provides a `sus.cpp` file with the following contents we need to figure out the meaning of the keywords:

```c
#define skibidi ?

using namespace skibidi;

#define hawk ?
#define pressed ?
#define crash_out ?
#define ate ?
#define twin ?
#define periodt ?
#define vibe ?
#define blud ?
#define delulu ?
#define uhh ?
#define slay ?
#define dap ?
#define yap ?
#define diff ?
#define lit ?
#define free ?
#define stan ?
#define savage ?
#define hop_off ?
#define take_a_seat ?
#define amped ?
#define tuah ?
#define gucci ?
#define finna ?
#define rent ?
#define tea ?
#define flex ?
#define mid ?
#define cancelled ?
```

**AFTER SOME MANUAL WORK**, we can figure out the following mapping:

```c
#define skibidi std

using namespace skibidi;

#define hawk if
#define pressed -
#define crash_out }
#define ate +
#define twin ==
#define periodt ;
#define vibe while
#define blud char
#define delulu %
#define uhh ,
#define slay return
#define dap {
#define yap cout
#define diff <
#define lit int
#define free ]
#define stan =
#define savage NULL
#define hop_off )
#define take_a_seat endl
#define amped *
#define tuah else
#define gucci string
#define finna (
#define rent [
#define tea <<
#define flex >
#define mid /
#define cancelled break
```
