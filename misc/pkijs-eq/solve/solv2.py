from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
from asn1crypto import cms
import datetime

def create_cert(subject, pubkey=None, issuer=None, issuer_privkey=None):
    one_day = datetime.timedelta(1, 0, 0)
    if type(subject) == str:
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    private_key = None
    if pubkey is None:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        pubkey = private_key.public_key()

        if issuer is None:
            assert issuer_privkey is None
            issuer_privkey = private_key
            issuer = subject

        if issuer_privkey is None:
            issuer_privkey = private_key

    assert issuer is not None and issuer_privkey is not None

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(pubkey)
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    certificate = builder.sign(private_key=issuer_privkey, algorithm=hashes.SHA256())
    return certificate, private_key or issuer_privkey


root_crt = x509.load_pem_x509_certificate(open('../src/root.crt', 'rb').read())
my_crt, my_key = create_cert('my cert', pubkey=None, issuer=root_crt.issuer, issuer_privkey=None)

my_crt_der = my_crt.public_bytes(serialization.Encoding.DER)
root_crt_der = root_crt.public_bytes(serialization.Encoding.DER)

my_crt_kid = cms.Certificate.load(my_crt_der).public_key.sha1
data = b'I can forge a signed message!'
sig = my_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
sd = cms.SignedData({
    'version': 'v1',
    'encap_content_info': {
        'content_type': 'data',
        'content': data
    },
    'digest_algorithms': [
        {
            'algorithm': 'sha256',
            'parameters': None
        }
    ],
    'certificates': [
        cms.CertificateChoices.load(my_crt_der),
        cms.CertificateChoices.load(my_crt_der[:-1] + b'x'),
        cms.CertificateChoices.load(root_crt_der),
        cms.CertificateChoices.load(root_crt_der[:-1] + b'x'),
    ],
    'signer_infos': [
        {
            'version': 'v1',
            'digest_algorithm': {
                'algorithm': 'sha256',
                'parameters': None
            },
            'signature_algorithm': {
                'algorithm': 'sha256_rsa',
                'parameters': None
            },
            'signature': sig,
            'sid': cms.SignerIdentifier({
                'subject_key_identifier': my_crt_kid
            })
        }
    ]
})
ci = cms.ContentInfo({
    'content_type': 'signed_data',
    'content': sd
})

open('win.bin', 'wb').write(ci.dump())

# http -f POST http://localhost:1337/upload cms@./win.bin
