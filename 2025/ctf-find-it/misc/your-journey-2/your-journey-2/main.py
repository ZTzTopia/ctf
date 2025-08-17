import re

from hidden import *
from word import *

while True:
    ans = (
        input(
            f'{lagu}\nHmm keknya ada yang salah sama lagunya, bukannya "Ayo Ayo Ganyang si b.e.b.a.n 🌸"\n$'
        )
        .strip()
        .lower()
    )

    if any(char in ans for char in block):
        print(
            f'\nSayang sekali, kamu salah pilih kata-kata. Sekarang "oknum" sudah naik jabatan\n'
        )
        break
    if not re.match("^[\x20-\x7E]*$", ans):
        print("\nEa mau coba bukan huruf yak :>\n")
        break
    try:
        eval(ans + "()")
        print("Apakah ini akhir yang benar\n")
    except Exception as e:
        print(e)
        print(f'\n{ascii2}\nOh tidak, kamu diserang "Kawan-kawan oknum"\n')
        break
