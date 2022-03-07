import sys
import random
import base64
import subprocess
from OpenSSL import crypto, SSL

def createCert():
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().C = "US"
    #cert.get_subject().ST = "California"
    #cert.get_subject().L = "La Jolla"
    #cert.get_subject().O = "University of California, San Diego"
    #cert.get_subject().OU = "UCSD"
    #cert.get_subject().CN = 'ucsd.edu'
    cert.set_serial_number(int(random.random() * sys.maxsize))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')
    return k, cert

def createPkcs12(passphrase=None, cert=None, k=None):
    if cert is None or k is None:
        k, cert = createCert()

    pkcs = crypto.PKCS12()
    pkcs.set_privatekey(k)
    pkcs.set_certificate(cert)
    return base64.b64encode(pkcs.export(passphrase=passphrase)).decode()

def _createPkcs12(passphrase=None):
    c1 = 'openssl req -x509 -new -nodes -sha256 -utf8 -days 3650 -newkey rsa:2048 -subj "/C=US" '\
        + '-keyout server.key -out server.crt'
    c2 = "openssl pkcs12 -export -in server.crt -inkey server.key -out server.pfx -passout pass:'%s'" % passphrase
    subprocess.check_output(c1, shell=True)
    subprocess.check_output(c2, shell=True)
    with open('server.pfx', 'rb') as f:
        return base64.b64encode(f.read()).decode()

if __name__ == '__main__':
    #k = crypto.load_privatekey(crypto.FILETYPE_PEM, open('priv.key').read())
    #cert = crypto.load_certificate(crypto.FILETYPE_PEM, open('cert.crt').read())
    _, __ = createCert()
    #s = _createPkcs12(b'chtsec')#, cert, k)
    #with open('gogo.pfx', 'wb') as f:
    #    f.write(base64.b64decode(s))
