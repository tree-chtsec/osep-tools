class Manager:
    
    def __init__(self, _workloads=None):
        self.workloads = [] if _workloads is None else list(_workloads)

    def add(self, desc1, desc2, command):
        self.workloads.append(dict(desc1=desc1, desc2=desc2, cmd=command))

    def getCmd(self, desc1=None, desc2=None, n=1):
        result = []
        for w in self.workloads:
            if (desc1 is None or desc1 == w['desc1']) and (desc2 is None or desc2 == w['desc2']):
                result.append(w['cmd'])
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
