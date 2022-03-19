# SMB Audit

**ssh-audit** is a tool for SMB configuration auditing.

```

  ███████╗███╗   ███╗██████╗      █████╗ ██╗   ██╗██████╗ ██╗████████╗
  ██╔════╝████╗ ████║██╔══██╗    ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
  ███████╗██╔████╔██║██████╔╝    ███████║██║   ██║██║  ██║██║   ██║   
  ╚════██║██║╚██╔╝██║██╔══██╗    ██╔══██║██║   ██║██║  ██║██║   ██║   
  ███████║██║ ╚═╝ ██║██████╔╝    ██║  ██║╚██████╔╝██████╔╝██║   ██║   
  ╚══════╝╚═╝     ╚═╝╚═════╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   

  By: SecuProject - Version: 0.0.1-Dev


usage: smb-audit.py -t IP_ADDRESS [-p PORT] [-d]

ssh-audit is a tool for SMB configuration auditing.

options:
  -h, --help            show this help message and exit
  -t [IP_ADDRESS], --target [IP_ADDRESS]
                        The IP address of the server (e.g. "192.168.1.1")
  -p [PORT], --port [PORT]
                        Samba Server Hostname or IP Address
  -l LIST, --list LIST  List of ip addresses to scan
  -d, --debug           Debug Mode On

```

## Requirement

- Impacket (https://github.com/SecureAuthCorp/impacket)
- Python 3

### Setup 

To install requirements:

```
pip3 install -r requirements.txt
```

## Features and Functionality

- Test smb version enable 
- Test anonymous login
- Test if signing is enable 
- List encryption algorithm

## Demo 

[![asciicast](https://asciinema.org/a/cHupwnCT2f7u8mwFP3pdEG8bj.svg)](https://asciinema.org/a/cHupwnCT2f7u8mwFP3pdEG8bj?autoplay=1)

## Source

- https://github.com/blark/checksmbv1
- https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html#CLIENTMAXPROTOCOL
- https://www.programcreek.com/python/?code=b17zr%2Fntlm_challenger%2Fntlm_challenger-master%2Fntlm_challenger.py
- https://github.com/byt3bl33d3r/CrackMapExec/blob/master/cme/protocols/smb.py

## Legal Disclaimer:

    This project is made for educational and ethical testing purposes only. Usage of this software for attacking targets without prior mutual consent is illegal. 
    It is the end user's responsibility to obey all applicable local, state and federal laws. 
    Developers assume no liability and are not responsible for any misuse or damage caused by this program.