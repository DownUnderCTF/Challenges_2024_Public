emuc2
============

## Adding the SSLKEYLOGFILE to Wireshark

- The challenge gives us a pcap and an SSLKEYLOGFILE. Let's open the pcap in wireshark. We can add the SSLKEYLOGFILE to wireshark using the method described in "Using the (Pre)-Master-Secret" here: https://wiki.wireshark.org/TLS

## Finding the C2 server from the PCAP & Understanding the API

- The challenge description mentioned the malware using HTTP. Let's look for that using the filter from the documentation earlier:  `tls and (http or http2)`

- The pcap is quite noisey, thought interestingly there is only 4 HTTP2 requests present, each to the same domain.

- The requests are as follows:
  1. A POST request to `https://forensics-emuc2-b6abd8652aa4.2024.ductf.dev/api/login` with the body `{ "username": "joospeh", "password": "n3v3r-g0nna-g1v3-th3-b1rds-up"}`
  2. A GET to `/api/env`
  3. A POST to `/api/env` with the body as plaintext environment variables from malware
  4. A GET to `/api/flag`

- Putting that together, looks like this C2 collects environment variables from it's victims and stores then in `/api/env`. Additionally, for this challenege looks like we need to get whatever is in `/api/flag`.

- Look at the website, `https://forensics-emuc2-b6abd8652aa4.2024.ductf.dev/api/login`, we find it's alive and well. Logging in with the credentials seen in the PCAP gives us a successful login with the text `Subject 0 does not have permissions to view this flag.`

- Looking at the requests our browser made, it appears we have successfully gotten a JWT from `/api/login`. Decoding this with https://jwt.io we find that it has a field called `subject_id` which is currently set to 0. Looks like that is what we are going to have to change. So we need a way to sign our own JWTs.

- Using that JWT to GET `/api/env`, we recieve a list of randomly looking 32 character strings.

- Using it to POST `/api/env`, we recieve a message saying that upload has been successful and we get a filename that is a 32 character long string. With this, we can infer that the strings we saw in our GET request must also be filenames.

- A common pattern for APIs that read a list with GET and write a single instance with POST (or PUT) is to allow you to read a single instance with a GET to `/post_location/<id>`

- Trying `/api/env/<filename>` we see that is also the case here.

## Finding the environment variables

- If we enumerate over the filenames we found in our GET to `/api/env`, we see that there are a bunch of environment variable dumps.

- They all seem to have a common pattern too. The first line is a timestamp in Zulu time and the rest are environment variables.

- This is true for all the challenge relevant files. The ones made by competitors will have `This file is intentionally blank.` and can be safely ignored.

- If we enumerate over all the files, extract these timestamps and sort them, we find they are all in 2024, except for one which is in 2023.

- Looking at this 2023 file more, we find an environment variable called `JWT_SECRET`. Let's copy that.

```py
import requests

r = requests.get("http://forensics-emuc2-b6abd8652aa4.2024.ductf.dev/api/login")

s = []
for item in r.json():
     if item != "Do0R2dP8lOfVnqy2Q4TUAfhlVNgrmXYg":
         e = requests.get(f"http://forensics-emuc2-b6abd8652aa4.2024.ductf.dev/api/env/{item}")
         s.append((e.text.split('\n')[0], item))
s = sorted(s)

print("Earliest environment variables uploaded:", s[0])

t = requests.get(f"http://forensics-emuc2-b6abd8652aa4.2024.ductf.dev/api/env/{s[0][1]}")

print("Found JWT secret:")
for item in t.text.split("\n"):
    if "JWT" in item:
        print(item)
```

## Forging your own JWT

- Get a valid JWT from the API:

```bash
curl -X POST -H "Content-Type: application/json" http://forensics-emuc2-b6abd8652aa4.2024.ductf.dev/api/login -d '{"username": "admin", "password": "admin"}'
```

- Go to https://jwt.io and copy that token into the `Encoded` box.

- In the `Decoded` section, at the bottom find the `your-256-bit-secret` field and enter the JWT we found in the environment variables. Do NOT mark this as being Base64 encoded.

- Modify the `subject_id` field of the PAYLOAD to `1`

- Copy the `Encoded` section and use this as your auth token to the API when requesting the flag

```bash
curl http://forensics-emuc2-b6abd8652aa4.2024.ductf.dev/api/flag -H "Authorization: Bearer <your new JWT>"
```

- If you get `{"error":"Error validating JWT token - Expired Token"}`, arbitrary bump the number in the `exp` field of the PAYLOAD. That will extend your expiry time.

- ???

- If all goes right, you should have the flag! :partyparrot: