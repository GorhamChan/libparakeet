#!/usr/bin/env python3

# Helper script to unroll the md5_transform loop.

elements = ["a", "b", "c", "d"]
fns = ["FF", "GG", "HH", "II"]
for i in range(0, 64):
    params = ", ".join(elements)
    elements.insert(0, elements.pop())
    print(f"{fns[i//16]}({params}, {i});", end="")
    if i % 16 == 0:
        print("\n")

    # FF(AA, BB, CC, DD, 0);
    # FF(DD, AA, BB, CC, 1);
    # FF(CC, DD, AA, BB, 2);
    # FF(BB, CC, DD, AA, 3);
    # ...
