import zlib
from subprocess import Popen, PIPE, STDOUT

FLASH_SIZE = 0x80000
challenge_id = 0x000000_01

card_serial = int(input("Card serial:"))

card_header = b'CFC1' + card_serial.to_bytes(4, 'big') + challenge_id.to_bytes(4, 'big')
card_header += zlib.crc32(card_header).to_bytes(4, 'big')

card_header += b"\xFF" * (FLASH_SIZE - len(card_header))

p = Popen(['flashrom', '--program', 'ch341a_spi', '-w', '-'], stdin=PIPE)
p.communicate(input=card_header)

p = Popen(['ch341eeprom', '-v', '-s', '24c02', '-c', '7', '-w', 'eeprom.bin'], stdin=PIPE)
p.communicate(input=card_header)

p = Popen(['ch341eeprom', '-v', '-s', '24c02', '-c', '7', '-V', 'eeprom.bin'], stdin=PIPE)
p.communicate(input=card_header)
