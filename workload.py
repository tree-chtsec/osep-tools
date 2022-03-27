import re
import os

class Manager:
    
    def __init__(self, _workloads=None, _stageless=False, tempUtil=None):
        self.workloads = [] if _workloads is None else list(_workloads)
        self.stageless = _stageless
        self.tempUtil = tempUtil

    def add(self, desc1, desc2, command):
        self.workloads.append(dict(desc1=desc1, desc2=desc2, cmd=command))

    def getCmd(self, desc1=None, desc2=None, n=1):
        result = []
        for w in self.workloads:
            if (desc1 is None or desc1 == w['desc1']) and (desc2 is None or desc2 == w['desc2']):
                _cmd = self.get_iex_data(w['cmd']) if self.stageless else w['cmd']
                result.append(_cmd)
        if len(result) < n:
            print('Manager::getCmd find %d record. But specified n = %d' % (len(result), n))
            return ''
        if n == 1: # auto-flatten
            return result[0]
        return result[:n]

    def __str__(self):
        out = ''
        for w in self.workloads:
            r = w['desc1']
            if w['desc2']:
                r = r+' - '+w['desc2']
            r += '\n\t'+w['cmd'].replace('\n', '\n\t')+'\n'
            out += r + '\n'
        return out

    def get_iex_data(self, cmd):
        _cmd = cmd
        if cmd.lower().startswith('iwr'):
            _ = cmd.replace('`', '')
            _filename = re.search(r'http(.+)/([^/ ]+)', _).group(2)
            _cmd = open(os.path.join(self.tempUtil.getTempDir(), _filename)).read().strip()
        return _cmd

    def export_cheatsheet(self, filename='osep_hunter.md'):
        content = '# attackSuite\n% attacksuite, osep, pen-300\n#plateform/multiple #target/remote #cat/OSEP\n'
        for w in self.workloads:
            title = '%s %s' % (w['desc1'], (' - ' + w['desc2']) if w['desc2'] else '')
            content += '\n'.join(['## %s' % title, '```', w['cmd'], '```', ''])
        folder = os.path.expanduser('~/.cheats')
        if not os.path.exists(folder):
            os.makedirs(folder)
        self.cheat = os.path.join(folder, filename)
        with open(self.cheat, 'w') as f:
            f.write(content)

    def remove_cheatsheet(self):
        os.remove(self.cheat)

    def sort(self):
        self.workloads.sort(key = lambda x: x['desc1'])
