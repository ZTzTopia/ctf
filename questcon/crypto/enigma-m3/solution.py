from enigma.machine import EnigmaMachine

machine = EnigmaMachine.from_key_sheet(
    rotors='I II III',
    reflector='B',
    ring_settings=[3, 3, 3],
    plugboard_settings='AG BH'
)

machine.set_display('ABC')

ciphertext = 'ymnjp znmjo gteqj cjwwh qljtd nprmp g'
ciphertext = ciphertext.replace(' ', '')
plaintext = machine.process_text(ciphertext)

print("Decrypted message:", plaintext)
