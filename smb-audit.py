from typing import Literal
from impacket.smbconnection import SMBConnection
from impacket import smb
import argparse
import socket
import logging

# https://www.cyberciti.biz/faq/how-to-configure-samba-to-use-smbv2-and-disable-smbv1-on-linux-or-unix/
SMB2_DIALECT_002      = 0x0202
SMB2_DIALECT_21       = 0x0210
SMB2_DIALECT_30       = 0x0300
SMB2_DIALECT_302      = 0x0302  #SMB 3.0.2
SMB2_DIALECT_311      = 0x0311  #SMB 3.1.1

class bcolors:
    HEADER  = '\033[95m'
    OKBLUE  = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL    = '\033[91m'
    ENDC    = '\033[0m'
    BOLD    = '\033[1m'


def highlightGreen(msg:str)->str:
    return bcolors.OKGREEN + msg + bcolors.ENDC
def highlightRed(msg:str)->str:
    return bcolors.FAIL + msg + bcolors.ENDC
def StyleBold(msg:str)->str:
    return bcolors.BOLD + msg + bcolors.ENDC
def highlight(msg:str,mode:bool)->str:
    if(mode):
        return highlightGreen(msg)
    else:
        return highlightRed(msg)

def get_server_info(smb_client: SMBConnection) -> dict:
    server_info = {}

    server_info['domain']  = smb_client.getServerDomain()
    server_info['name']    = smb_client.getServerName()
    server_info['os']      = smb_client.getServerOS()

    server_info['OSBuild'] = smb_client.getServerOSBuild()
    server_info['OSMajor'] = smb_client.getServerOSMajor()
    server_info['OSMinor'] = smb_client.getServerOSMinor()

    return server_info
def login_anonymous(ip_address: str, port:int=445) -> dict:
    smb_client = SMBConnection('*SMBSERVER', ip_address, sess_port=port) # , preferredDialect=dialect
    try:
        smb_client.login('', '')
        server_info = get_server_info(smb_client)
        smb_client.logoff()
        return [True,server_info]
    except Exception as e:
        logging.error('Failed %s', e)
    return [False,None]
def print_server_information(is_anonymous:bool,server_info:dict) -> None:
    print("[-] Server information\n")

    print("Allow %s login\t" % StyleBold("anonymous"),end="")
    if(not is_anonymous):
        print("%s" % highlight("no",True))
        return 
    print("%s" % highlight("yes",False))

    if(server_info['domain']):
        print('Server domain:\t\t%s' % server_info['domain'])
    if(server_info['name']):
        print('Server name: \t\t%s' % server_info['name'])
    if(server_info['os']):
        print('Server OS: \t\t%s' % server_info['os'])



def test_smb_version(ip_address:str, port:int=445,dialect:Literal=SMB2_DIALECT_311, debug=False):
    try:
        smb_client = SMBConnection('*SMBSERVER', ip_address, sess_port=port, preferredDialect=dialect)
        if isinstance(smb_client, SMBConnection):
            return True
    except Exception as e:
        logging.error('Failed %s', e)
    return False

def check_smb_version(ip_address:str, port:int=445) -> list:
    print("\n[-] Testing smb versions\n")
    tab_version = [
        {'diablect':smb.SMB_DIALECT,    'string':"1",   'isEnable':False,'secure':False},
        {'diablect':SMB2_DIALECT_002,   'string':"2.0", 'isEnable':False,'secure':True},
        {'diablect':SMB2_DIALECT_21,    'string':"2.1", 'isEnable':False,'secure':True},
        {'diablect':SMB2_DIALECT_30,    'string':"3.0", 'isEnable':False,'secure':True},
        {'diablect':SMB2_DIALECT_302,   'string':"3.0.2",'isEnable':False,'secure':True},
        {'diablect':SMB2_DIALECT_311,   'string':"3.1.1",'isEnable':False,'secure':True}
    ]

    for version in tab_version:
        print(StyleBold("SMB %5s" % version['string'])+"\t",end="")
        version['isEnable'] = test_smb_version(ip_address,port,version['diablect'])
        if(version['isEnable']):
            print(highlight("offered",version['secure']))
        else:
            print(highlight("not offered",not version['secure']))
    return tab_version
        
def get_capabilities(capabilities:int)-> list:
    tab_capabilities = []
    CAP_RAW_MODE                            = 0x00000001
    CAP_MPX_MODE                            = 0x0002
    CAP_UNICODE                             = 0x0004
    CAP_LARGE_FILES                         = 0x0008
    CAP_EXTENDED_SECURITY                   = 0x80000000
    CAP_USE_NT_ERRORS                       = 0x40
    CAP_NT_SMBS                             = 0x10
    CAP_LARGE_READX                         = 0x00004000
    CAP_LARGE_WRITEX                        = 0x00008000
    CAP_RPC_REMOTE_APIS                     = 0x20

    if(capabilities & CAP_RAW_MODE):
        tab_capabilities.append("CAP_RAW_MODE")
    if(capabilities & CAP_MPX_MODE):
        tab_capabilities.append("CAP_MPX_MODE")
    if(capabilities & CAP_UNICODE):
        tab_capabilities.append("CAP_UNICODE")
    if(capabilities & CAP_LARGE_FILES):
        tab_capabilities.append("CAP_LARGE_FILES")
    if(capabilities & CAP_EXTENDED_SECURITY):    
        tab_capabilities.append("CAP_EXTENDED_SECURITY")
    if(capabilities & CAP_USE_NT_ERRORS):
        tab_capabilities.append("CAP_USE_NT_ERRORS")
    if(capabilities & CAP_NT_SMBS):
        tab_capabilities.append("CAP_NT_SMBS")
    if(capabilities & CAP_LARGE_READX):
        tab_capabilities.append("CAP_LARGE_READX")
    if(capabilities & CAP_LARGE_WRITEX):
        tab_capabilities.append("CAP_LARGE_WRITEX")
    if(capabilities & CAP_RPC_REMOTE_APIS):
        tab_capabilities.append("CAP_RPC_REMOTE_APIS")
    return tab_capabilities


def check_signing(ip_address:str, port:int,tab_version:list, debug=False):
    for version in tab_version:
        if(version['isEnable'] and version['string'] != '1'):
            try:
                smb_client = SMBConnection('*SMBSERVER', ip_address, preferredDialect=version['diablect'], sess_port=port)
                if isinstance(smb_client, SMBConnection):
                    print("\n%s"% StyleBold("SMB "+version['string']))
                    print("Require Message Signing \t",end="")
                    if smb_client._SMBConnection._Connection['RequireSigning']:
                        print(highlight("yes",True))
                    else:
                        print(highlight("no",False))
                        
                    print("Require Secure Negotiate\t",end="")
                    if smb_client._SMBConnection.RequireSecureNegotiate:
                        print(highlight("yes",True))
                    else:
                        print(highlight("no",False))
                        
                    print("Require Message Signing \t",end="")
                    if smb_client._SMBConnection.RequireMessageSigning:
                        print(highlight("yes",True))
                    else:
                        print(highlight("no",False))


                    print("Client Require Message Signing \t",end="")
                    #print("Client Security Mode \t",end="")
                    if smb_client._SMBConnection._Connection['ClientSecurityMode']:
                        print(highlight("yes",True))
                    else:
                        print(highlight("no",False))
                    print("Server Require Message Signing \t",end="")
                    #print("Server Security Mode \t",end="")
                    if smb_client._SMBConnection._Connection['ServerSecurityMode']:
                        print(highlight("yes",True))
                    else:
                        print(highlight("no",False))

                    print("Client Capabilities:   \t\t"+str(get_capabilities(smb_client._SMBConnection._Connection['ClientCapabilities'])))
                    get_capabilities(smb_client._SMBConnection._Connection['ClientCapabilities'])
                    print("Server Capabilities:   \t\t"+str(get_capabilities(smb_client._SMBConnection._Connection['ServerCapabilities'])))
                    get_capabilities(smb_client._SMBConnection._Connection['ServerCapabilities'])

                    print("Encryption Algorithm List:\t"+str(smb_client._SMBConnection.EncryptionAlgorithmList))
            except Exception as e:
                logging.error('Failed %s', e)

def port_check(ip_address:str, port:int):
   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   try:
      s.connect((ip_address, port))
      s.shutdown(2)
      return True
   except:
      return False

def MainBanner() -> None:
    print('')
    print('  ███████╗███╗   ███╗██████╗      █████╗ ██╗   ██╗██████╗ ██╗████████╗')
    print('  ██╔════╝████╗ ████║██╔══██╗    ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝')
    print('  ███████╗██╔████╔██║██████╔╝    ███████║██║   ██║██║  ██║██║   ██║   ')
    print('  ╚════██║██║╚██╔╝██║██╔══██╗    ██╔══██║██║   ██║██║  ██║██║   ██║   ')
    print('  ███████║██║ ╚═╝ ██║██████╔╝    ██║  ██║╚██████╔╝██████╔╝██║   ██║   ')
    print('  ╚══════╝╚═╝     ╚═╝╚═════╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   \n')
    print('  By: SecuProject - Version: 0.0.1-Dev\n\n')
def ManageArg() -> str:
    parser = argparse.ArgumentParser(description='ssh-audit is a tool for SMB configuration auditing.', usage='%(prog)s -t IP_ADDRESS [-p PORT] [-d]')
    parser.version = 'smb-audit version: 0.0.1-Dev'
    parser.add_argument('-t','--target', metavar='[IP_ADDRESS]', type=str, help='The IP address of the server (e.g. "192.168.1.1")', required=True)
    parser.add_argument("-p", "--port", metavar='[PORT]', type=int, help="Samba Server Hostname or IP Address",default=445)
    parser.add_argument("-d", "--debug", help="Debug Mode On", action="store_true")

    try:
        args = parser.parse_args()
    except:
        exit(0)

    if(args.debug):
        logging.basicConfig(filename='smb-audit.log', encoding='utf-8', level=logging.DEBUG,format='%(asctime)s - [%(levelname)s] - %(message)s', datefmt='%d/%m/%Y %I:%M:%S %p')
    else:
        logging.basicConfig(filename='smb-audit.log', encoding='utf-8', level=logging.INFO,format='%(asctime)s - [%(levelname)s] - %(message)s', datefmt='%d/%m/%Y %I:%M:%S %p')
        
    return [args.target,args.port]

if __name__ == '__main__':
    MainBanner()
    ip_address, port = ManageArg()

    logging.info('Started')
    if(not port_check(ip_address, port)):
        print("[x] %s\n" % highlightRed("The port %i is not open (%s) !"% (port, ip_address)))
        logging.error('Port close')
        logging.info('Finished')
        exit(1)


    print("Target ip address: %s\n\n" % StyleBold(ip_address))

    
    is_anonymous,server_info = login_anonymous(ip_address, port)
    print_server_information(is_anonymous, server_info)

    tab_version = check_smb_version(ip_address, port)

    check_signing(ip_address, port, tab_version)
    logging.info('Finished')