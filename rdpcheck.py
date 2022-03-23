import subprocess

pipe = subprocess.PIPE

def info2str(o):
    s = "/v:%s /u:'%s'" % (o['target'], o['username'])
    if 'password' in o:
        s += " /p:'%s' +auth-only" % o['password']
    #elif 'ntlm' in o:
    #    s += ' /pth:%s' % o['ntlm']
    else:
        raise Exception("No password provided")

    if 'domain' in o:
        s += ' /d:%s' % o['domain']

    return s

#print('Restricted Admin mode default disabled. You can\'t PTH even if you have RDP access.')
#print('Nevertheless, hydra is enough for brute forcing...')

# timeout is useless, just to prevent hanging infinitely
def run(target, username, password, domain=None, useProxy=False, timeout=60):
    domain = domain or '.'
    if useProxy:
        binary = 'proxychains xfreerdp'
    else:
        binary = 'xfreerdp'
    auth_info = info2str(dict(target=target, username=username, password=password, domain=domain))
    cmd = '%s %s /cert-ignore' % (binary, auth_info)
    #print(cmd)
    p = subprocess.Popen(cmd, shell=True, stderr=pipe, stdout=pipe, stdin=pipe)
    try:
        _ = p.communicate(timeout=timeout)
        if p.returncode == 0:
            return 1
        else:
            return 0
    except subprocess.TimeoutExpired:
        return -1
