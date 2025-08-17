---
title: "Decode Runner"
category: Miscellaneous
tags: 
draft: false
completedDuringEvent: true
submitted: true
flag: PWNME{d4m_y0U_4r3_F4st!_4nd_y0u_kn0w_y0ur_c1ph3rs!}
---
> Welcome to Decode Runner ! You will receive 100 encoded words. Your goal is to decode them and send back the decoded word. You have 3 seconds to respond to each word. Good luck!
>
> Author : `Offpath`
>
> Flag format: `PWNME{.........................}`
>
> Connect : `nc --ssl [host] 443`

by Offpath

---

So we are given a service that sends us encoded words and we have to decode them and send back the decoded word. We have 3 seconds to respond to each word. After connecting to the service, we are given a hint and the encoded word. The hint is used to determine which decoding function to use.

We can use [dcode.fr cipher indetifier](https://www.dcode.fr/cipher-identifier) to identify the cipher used in the encoded word. After many conversations with **ChatGPT**, **GitHub Copilot**, **Deepseek**, and some code searching to write the decoding functions for each hint, I came up with the following script:

```py
def trithemius_decrypt(ciphertext, initial_shift=3):
    decrypted_text = ""
    for i, char in enumerate(ciphertext):
        shift = initial_shift + i  # Incremental shift
        decrypted_char = chr(((ord(char) - ord('a') - shift) % 26) + ord('a'))
        decrypted_text += decrypted_char
    return decrypted_text

def shankar_speech_defect(text):
    table = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    table2 = "DFGHJKLMNUOPQRSTIVWXYZBACE"
    return "".join([table2[table.index(c)] if c in table else c for c in text])

def nato_phonetic_alphabet(text):
    table = {
        'Alfa': 'A', 'Bravo': 'B', 'Charlie': 'C', 'Delta': 'D', 'Echo': 'E', 'Foxtrot': 'F', 'Golf': 'G', 'Hotel': 'H',
        'India': 'I', 'Juliett': 'J', 'Kilo': 'K', 'Lima': 'L', 'Mike': 'M', 'November': 'N', 'Oscar': 'O', 'Papa': 'P',
        'Quebec': 'Q', 'Romeo': 'R', 'Sierra': 'S', 'Tango': 'T', 'Uniform': 'U', 'Victor': 'V', 'Whiskey': 'W', 'X-ray': 'X',
        'Yankee': 'Y', 'Zulu': 'Z', 'Zero': '0', 'One': '1', 'Two': '2', 'Three': '3', 'Four': '4', 'Five': '5', 'Six': '6',
        'Seven': '7', 'Eight': '8', 'Nine': '9', 'Dash': '-', 'Stop': '.'
    }
    return "".join([table[c] for c in text.split()])

def chuck_norris_code(text):
    # Splitting the encoded text into parts
    parts = text.split()
    
    binary_string = ""
    
    # Iterate through the encoded chunks in pairs
    for i in range(0, len(parts), 2):
        prefix = parts[i]  # Either "00" (for 0s) or "0" (for 1s)
        sequence = parts[i+1]  # The sequence of zeroes indicating length

        if prefix == "00":  # Represents a sequence of 0s
            binary_string += "0" * len(sequence)
        elif prefix == "0":  # Represents a sequence of 1s
            binary_string += "1" * len(sequence)
    
    # Convert binary string to ASCII text
    decoded_text = "".join(chr(int(binary_string[i:i+7], 2)) for i in range(0, len(binary_string), 7))
    
    return decoded_text

WABUN = {
    'A': '--.--',   # a
    'I': '.-',      # i
    'U': '..-',     # u
    'E': '-.---',   # e
    'O': '.-...',   # o
    
    'KA': '.-.-',    # ka
    'KI': '-.-..',   # ki
    'KU': '...-',    # ku
    'KE': '-.--',    # ke
    'KO': '----',    # ko
    
    'SA': '-.-.-',   # sa
    'SHI': '--.-..',  # shi
    'SU': '---.-',   # su
    'SE': '.---.',   # se
    'SO': '---.',    # so
    
    'TA': '-.',      # ta
    'CHI': '..-.',    # chi
    'TSU': '.--.',    # tsu
    'TE': '.-.--',   # te
    'TO': '..-..',   # to
    
    'NA': '.-.',     # na
    'NI': '-.--.',   # ni
    'NU': '....',    # nu
    'NE': '--.-',    # ne
    'NO': '..--',    # no
    
    'HA': '-...',    # ha
    'HI': '--..-',   # hi
    'FU': '--..',    # fu
    'HE': '.',       # he
    'HO': '-..',     # ho
    
    'MA': '-..-',    # ma
    'MI': '..-.-',   # mi
    'MU': '-',       # mu
    'ME': '-...-',   # me
    'MO': '-..-.',   # mo
    
    'YA': '.--',     # ya
    'YU': '-..--',   # yu
    'YO': '--',      # yo
    
    'RA': '...',     # ra
    'RI': '--.',     # ri
    'RU': '-.--.',   # ru
    'RE': '---',     # re
    'RO': '.-.-.',   # ro
    
    'WA': '-.-',     # wa
    'WO': '.---',    # wo
    'N': '.-.-.',    # n
    
    ',': '.-..-',   # Japanese comma
    # 'PERIOD': '.-.-.-',  # Japanese period
    # 'LPAREN': '-.--.',   # Left parenthesis 
    # 'RPAREN': '.-..-.',  # Right parenthesis
    # 'QUOTE_OPEN': '.-.-.',   # Opening quote
    # 'QUOTE_CLOSE': '.-.-..',  # Closing quote
    
    '1': '.----',
    '2': '..---',
    '3': '...--',
    '4': '....-',
    '5': '.....',
    '6': '-....',
    '7': '--...',
    '8': '---..',
    '9': '----.',
    '0': '-----',
    
    'SPACE': '/',        # Word separator
}

# Create reverse mapping for decoding
REVERSE_WABUN = {v: k for k, v in WABUN.items()}

def wabun_code(text):
    # decode the wabun code
    return "".join([REVERSE_WABUN.get(c, c) for c in text.split()])

# Define the letter and figure shift codes for Baudot (5-bit code)
LETTERS_SHIFT = 0b11111  # 31 - Shift to letters set
FIGURES_SHIFT = 0b11011  # 27 - Shift to figures set

# Original Baudot code (Murray code/ITA1)
# Maps 5-bit codes to characters in the letters set
BAUDOT_LETTERS = {
    0b00000: ' ',    # NULL/BLANK
    0b00001: 'E',
    0b00010: 'LF',   # Line Feed
    0b00011: 'A',
    0b00100: ' ',    # SPACE
    0b00101: 'S',
    0b00110: 'I',
    0b00111: 'U',
    0b01000: 'CR',   # Carriage Return
    0b01001: 'D',
    0b01010: 'R',
    0b01011: 'J',
    0b01100: 'N',
    0b01101: 'F',
    0b01110: 'C',
    0b01111: 'K',
    0b10000: 'T',
    0b10001: 'Z',
    0b10010: 'L',
    0b10011: 'W',
    0b10100: 'H',
    0b10101: 'Y',
    0b10110: 'P',
    0b10111: 'Q',
    0b11000: 'O',
    0b11001: 'B',
    0b11010: 'G',
    0b11011: 'FIGS', # Figures shift
    0b11100: 'M',
    0b11101: 'X',
    0b11110: 'V',
    0b11111: 'LTRS', # Letters shift
}

# Maps 5-bit codes to characters in the figures set
BAUDOT_FIGURES = {
    0b00000: ' ',    # NULL/BLANK
    0b00001: '3',
    0b00010: 'LF',   # Line Feed
    0b00011: '-',
    0b00100: ' ',    # SPACE
    0b00101: "'",    # Bell signal in some implementations
    0b00110: '8',
    0b00111: '7',
    0b01000: 'CR',   # Carriage Return
    0b01001: '$',    # WRU (Who are you?) in some implementations
    0b01010: '4',
    0b01011: "'",    # Bell
    0b01100: ',',
    0b01101: '!',
    0b01110: ':',
    0b01111: '(',
    0b10000: '5',
    0b10001: '+',
    0b10010: ')',
    0b10011: '2',
    0b10100: '#',    # Pound sign in some implementations
    0b10101: '6',
    0b10110: '0',
    0b10111: '1',
    0b11000: '9',
    0b11001: '?',
    0b11010: '&',
    0b11011: 'FIGS', # Figures shift
    0b11100: '.',
    0b11101: '/',
    0b11110: ';',
    0b11111: 'LTRS', # Letters shift
}

# Create reverse mappings for encoding
REVERSE_BAUDOT_LETTERS = {v: k for k, v in BAUDOT_LETTERS.items() if v not in ['LTRS', 'FIGS', 'CR', 'LF']}
REVERSE_BAUDOT_FIGURES = {v: k for k, v in BAUDOT_FIGURES.items() if v not in ['LTRS', 'FIGS', 'CR', 'LF']}

# Special control character mappings
CONTROL_CHARS = {
    '\n': 0b00010,  # LF
    '\r': 0b01000,  # CR
}

def baudot_code(baudot_codes):
    # decode the baudot code
    result = []
    current_shift = None
    
    for code in baudot_codes:
        # Handle shift codes
        if code == LETTERS_SHIFT:
            current_shift = LETTERS_SHIFT
            continue
        elif code == FIGURES_SHIFT:
            current_shift = FIGURES_SHIFT
            continue
            
        # If we haven't determined shift yet, default to letters
        if current_shift is None:
            current_shift = LETTERS_SHIFT
        
        # Decode based on current shift
        if current_shift == LETTERS_SHIFT:
            char = BAUDOT_LETTERS.get(code, '?')
        else:  # current_shift == FIGURES_SHIFT
            char = BAUDOT_FIGURES.get(code, '?')
        
        # Skip shift characters in output
        if char not in ['LTRS', 'FIGS']:
            if char == 'CR':
                result.append('\r')
            elif char == 'LF':
                result.append('\n')
            else:
                result.append(char)
    
    return ''.join(result)

def baudot_code_from_binary_string(binary_string):
    """Decode a binary string representation of Baudot code to text"""
    # Remove any whitespace and split into 5-bit chunks
    binary_string = binary_string.replace(' ', '')
    codes = []
    
    for i in range(0, len(binary_string), 5):
        if i + 5 <= len(binary_string):
            code = int(binary_string[i:i+5], 2)
            codes.append(code)
    
    return baudot_code(codes)

def leet_speak(text):
    table = {
        '4': 'a', '8': 'b', 'C': 'C', 'D': 'D', '3': 'e', 'F': 'F', '6': 'g', 'H': 'H',
        '1': 'i', 'J': 'J', 'K': 'K', 'L': 'L', 'M': 'M', 'N': 'N', '0': 'o', 'P': 'P',
        'Q': 'Q', 'R': 'R', '5': 's', '7': 't', 'U': 'U', 'V': 'V', 'W': 'W', 'X': 'X',
        'Y': 'Y', '2': 'z', '|<': 'k'
    }
    return "".join([table.get(c, c) for c in text])

def latin_gibberish(text):
    words = text.split()
    decrypted_words = []

    # Common Latin suffixes that may be appended
    suffixes = ["US", "UM", "A", "IS", "OS", "ES", "AE", "E", "I", "IT"]

    for word in words:
        # Remove the suffix if present
        for suffix in suffixes:
            if word.endswith(suffix.lower()):
                word = word[:-len(suffix)]
                break  # Stop after removing the first matching suffix

        # Reverse the remaining characters
        decrypted_word = word[::-1]
        decrypted_words.append(decrypted_word)

    return " ".join(decrypted_words)

guitar_chords = {
    "x24442": "B",
    "x02220": "A",
    "xx0232": "D",
    "320003": "G",
    "022100": "E",
    "133211": "F",
    "224442": "B",
    "032010": "C",
    "x35553": "C",
    "x57775": "D",
    "xx0212": "D",
    "x13331": "F",
    "355433": "G",
    "577655": "A",
    "799877": "B",
    "x32010": "C",
}

def guitar_chords_notation(text):
    return "".join([guitar_chords.get(c, c) for c in text.split()])



table = {
    '1': '..',
    '2': './',
    '3': '/-',
    '4': '//',
    '5': '-.',
    '6': '--',
    '7': '/.',
    '8': '-/',
    '9': '.-'
}

morse_table = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H',
    '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P',
    '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
    '-.--': 'Y', '--..': 'Z', '.----': '1', '..---': '2', '...--': '3', '....-': '4', '.....': '5',
    '-....': '6', '--...': '7', '---..': '8', '----.': '9', '-----': '0'
}

def morbit_decrypt(ciphertext , keyword):
    morse = ""
    for c in ciphertext:
        print(c)
        if c in table:
            morse += table[c]
        
    # split by /
    morse = morse.split('/')
    plaintext = ""

    for m in morse:
        if m in morse_table:
            plaintext += morse_table[m]
        else:
            plaintext += ' '
    
    return plaintext


from pwn import *

context.log_level = 'debug'

r = remote('decoderunner-6bc786c74ac9f4f0.deploy.phreaks.fr', 443, ssl=True)

r.recvuntil(b'and send back the decoded word. You have 3 seconds to respond to each word. Good luck!\n')
r.recvline()
r.recvline()
r.recvline()
while True:
    is_hint_or_cipher = r.recvline().strip().decode()
    is_hint_or_cipher = is_hint_or_cipher.split(': ')
    
    if is_hint_or_cipher[0] == 'cipher':
        r.sendline(nato_phonetic_alphabet(is_hint_or_cipher[1]).lower())
        continue

    hint = is_hint_or_cipher[1]
    r.recvuntil(b'cipher: ')
    cipher = r.recvline().strip().decode()

    known_cipher = {
        '4rC': 'arc',
        'D4N53r': 'danser',
        'xx0232 022100 320003 x02220 320003 022100': 'degage',
        '8r0U3773': 'brouette',
        'x24442 022100 x02220 xx0232 022100 xx0232': 'beaded',
        '00001 10010 00001 10110 10100 00011 01100 10000': 'elephant',
        '10111 00111 00011 01010 10000 10001': 'quartz',
        '11010 00111 00110 10000 00011 01010 00001': 'guitare',
        'x24442 x02220 xx0232 320003 022100 xx0232': 'badged',
        '00110 01100 10000 00001 01010 01100 00001 10000': 'internet',
        '10011 00011 10010 01010 00111 00101': 'walrus',
        '-.-.. -.- ..--': 'kiwano',
        '01011 11000 00111 00001 10000': 'gamte',
        '|<4N60Ur0U': 'kangourou',
        '5293212292': 'danser',
        '932932971': 'ananas',
        '5781972922': 'navire',
        '557121732': 'chien'
    }

    if cipher in known_cipher:
        r.sendline(known_cipher[cipher])
        continue

    if hint == '1337 ...':
        r.sendline(leet_speak(cipher).lower())
    elif hint == 'He can\'t imagine finding himself in CTF 150 years later...':
        r.sendline(baudot_code_from_binary_string(cipher).lower())
    elif hint == 'It looks like Morse code, but ...':
        r.sendline(wabun_code(cipher).lower())
    elif hint == 'Did you realy see slumdog millionaire ?':
        r.sendline(shankar_speech_defect(cipher).lower())
    elif hint == 'Born in 1462 in Germany...':
        r.sendline(trithemius_decrypt(cipher))
    elif hint == 'He can snap his toes, and has already counted to infinity twice ...':
        r.sendline(chuck_norris_code(cipher))
    elif hint == 'what is this charabia ???':
        r.sendline(latin_gibberish(cipher))
    elif hint == 'Hendrix would have had it...':
        r.sendline(guitar_chords_notation(cipher).lower())
    elif hint == 'A code based on pairs of dots and dashes. Think of a mix of Morse code and numbers... (AZERTYUIO)':
        r.sendline(morbit_decrypt(cipher, 'AZERTYUIO').lower())
```

I want to use dcode.fr API but it is not available for public they said? :(.
