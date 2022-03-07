from os.path import basename, getsize, join
import tempfile

def setTempDir(t):
    tempfile.tempdir = t

def getTempDir():
    return tempfile.tempdir

httpUrl = None
def setUrl(u):
    global httpUrl
    httpUrl = u

prefix = None
def setPrefix(p):
    global prefix
    prefix = p

def do_nothing(s):
    return s

def getBytesName(Bytes, encode_fn=do_nothing):
    with tempfile.NamedTemporaryFile(prefix=prefix, delete=False) as f:
        f.write(bytearray(encode_fn(Bytes)))
        return f.name

def getBytesUrl(Bytes, encode_fn=do_nothing):
    return '%s/%s' % (httpUrl, basename(getBytesName(Bytes, encode_fn)))

def getFileName(filename, encode_fn=do_nothing):
    with open(filename, 'rb') as f:
        data = f.read()
    return getBytesName(data, encode_fn)

def getFileUrl(filename, encode_fn=do_nothing):
    with open(filename, 'rb') as f:
        data = f.read()
    return getBytesUrl(data, encode_fn)

#======

def getUrlBytes(url, decode_fn=do_nothing):
    with open(join(tempfile.tempdir, url[len(httpUrl)+1:]), 'rb') as f:
        data = f.read()
    return decode_fn(data)

def getUrlSize(url, decode_fn=do_nothing):
    return len(getUrlBytes(url, decode_fn))
