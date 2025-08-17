import re

plaintext = []
shift_pressed = False

# Regex to extract keysym from the log line
keysym_regex = re.compile(r'keysym 0x([0-9a-fA-F]+)')

with open('keys.log', 'r') as file:
	for line in file:
		if 'KeyPress' in line or 'KeyRelease' in line:
			keysym_match = keysym_regex.search(line)
			if keysym_match:
				keysym = int(keysym_match.group(1), 16)

				if keysym == 0xffe1:
					if 'KeyPress' in line:
						shift_pressed = True
					elif 'KeyRelease' in line:
						shift_pressed = False
				elif keysym == 0xff0d:
					if 'KeyPress' in line:
						plaintext.append('\n')
				elif keysym == 0xff08:
					if 'KeyPress' in line:
						if plaintext:
							plaintext.pop()
				elif keysym == 0xff1b:
					if 'KeyPress' in line:
						plaintext.append('<Esc>')
				else:
					if 'KeyPress' in line:
						# Convert keysym to character
						try:
							char = chr(keysym)
							if shift_pressed:
								if char.isalpha():
									char = char.upper()
								else:
									plaintext.append('<Shift>')
							plaintext.append(char)
						except ValueError:
							pass

print(f'Plaintext: {"".join(plaintext)}')
