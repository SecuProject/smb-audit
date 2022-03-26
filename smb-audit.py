from typing import Literal
from impacket.smbconnection import SMBConnection
from impacket import smb
import argparse
import socket
import logging
import json

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

def print_error(message) -> None:
    format_msg = '[{}x{}] {}'.format(bcolors.FAIL,bcolors.ENDC,message)
    print(format_msg)
    logging.error(message)
def print_info(message) -> None:
    format_msg = '[{}i{}] {}'.format(bcolors.BOLD,bcolors.ENDC,message)
    print(format_msg)
    logging.info(message)

def highlightGreen(msg:str)->str:
    return bcolors.OKGREEN + msg + bcolors.ENDC
def highlightRed(msg:str)->str:
    return bcolors.FAIL + msg + bcolors.ENDC
def highlightBold(msg:str)->str:
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
        logging.debug('Failed {}'.format(e))
    return [False,None]
def print_server_information(is_anonymous:bool,server_info:dict) -> None:
    print("[-] Server information\n")

    print("Allow %s login:\t" % highlightBold("guest"),end="")
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
        logging.debug('Failed {}'.format(e))
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
        print(highlightBold("SMB %5s" % version['string'])+"\t",end="")
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


def handle_sign_info(msg:str,type:str,is_enable:bool)->dict:
    print(msg+ " \t",end="")
    if is_enable:
        print(highlight("yes",True))
    else:
        print(highlight("no",False))
    return {type:is_enable}

def check_signing(ip_address:str, port:int,tab_version:list, debug=False)->list:
    tab_info = []
    for version in tab_version:
        if(version['isEnable'] and version['string'] != '1'):
            try:
                smb_client = SMBConnection('*SMBSERVER', ip_address, preferredDialect=version['diablect'], sess_port=port)
                if isinstance(smb_client, SMBConnection):
                    print("\n%s"% highlightBold("SMB "+version['string']))
                    
                    smb_conn = smb_client._SMBConnection
                    smb_conn_con = smb_client._SMBConnection._Connection
                    tab_info_ver = {version['string']:[]}
                    
                    dict_req_signing = handle_sign_info("Require Signing\t\t",'RequireSigning',smb_conn_con['RequireSigning'])
                    dict_req_sec_neg = handle_sign_info("Require Secure Negotiate",'RequireSecureNegotiate',smb_conn.RequireSecureNegotiate)
                    dict_req_msg_signing = handle_sign_info("Require Message Signing",'RequireMessageSigning',smb_conn.RequireMessageSigning)
                    
                    dict_cli_req_msg_signing = handle_sign_info("Client Require Message Signing",'ClientSecurityMode',smb_conn_con['ClientSecurityMode'])
                    dict_serv_req_msg_signing = handle_sign_info("Server Require Message Signing",'ServerSecurityMode',smb_conn_con['ServerSecurityMode'])

                    tab_info_ver[version['string']].append(dict_req_signing)
                    tab_info_ver[version['string']].append(dict_req_sec_neg)
                    tab_info_ver[version['string']].append(dict_req_msg_signing)
                    tab_info_ver[version['string']].append(dict_cli_req_msg_signing)
                    tab_info_ver[version['string']].append(dict_serv_req_msg_signing)


                    cli_cap = get_capabilities(smb_conn._Connection['ClientCapabilities'])
                    serv_cap = get_capabilities(smb_conn._Connection['ServerCapabilities'])
                    print("Client Capabilities:   \t\t"+str(cli_cap))
                    print("Server Capabilities:   \t\t"+str(serv_cap))
                    print("Encryption Algorithm List:\t"+str(smb_conn.EncryptionAlgorithmList))

                    tab_info_ver[version['string']].append({'ClientCapabilities':cli_cap})
                    tab_info_ver[version['string']].append({'ServerCapabilities':serv_cap})
                    tab_info_ver[version['string']].append({'EncryptionAlgorithmList':smb_conn.EncryptionAlgorithmList})
                    tab_info.append(tab_info_ver)
            except Exception as e:
                logging.error('Failed {}'.format(e))
    return tab_info
def port_check(ip_address:str, port:int):
   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   try:
      s.connect((ip_address, port))
      s.shutdown(2)
      return True
   except:
      return False

def read_file_ip(file_name:str)->dict:
    tab_ip = []
    print_info('Opening file:\t{}'.format(highlightBold(file_name)))
    try:
        with open(file_name) as p_file:
            lines = p_file.readlines()
            for line in lines:
                tab_ip.append(line.rstrip("\n"))
    except Exception as e:
        print_error('Failed {}'.format(e))
        exit(-1)
    return tab_ip
def main_banner() -> None:
    print('')
    print('  ███████╗███╗   ███╗██████╗      █████╗ ██╗   ██╗██████╗ ██╗████████╗')
    print('  ██╔════╝████╗ ████║██╔══██╗    ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝')
    print('  ███████╗██╔████╔██║██████╔╝    ███████║██║   ██║██║  ██║██║   ██║   ')
    print('  ╚════██║██║╚██╔╝██║██╔══██╗    ██╔══██║██║   ██║██║  ██║██║   ██║   ')
    print('  ███████║██║ ╚═╝ ██║██████╔╝    ██║  ██║╚██████╔╝██████╔╝██║   ██║   ')
    print('  ╚══════╝╚═╝     ╚═╝╚═════╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   \n')
    print('  By: SecuProject - Version: 0.0.1-Dev\n\n')
def manage_arg() -> str:
    parser = argparse.ArgumentParser(description='ssh-audit is a tool for SMB configuration auditing.', usage='%(prog)s [-t IP_ADDRESS|-l FILE_NAME] [-p PORT] [-d] [-oj FILE_NAME]')
    parser.version = 'smb-audit version: 0.0.1-Dev'
    parser.add_argument('-t','--target', metavar='[IP_ADDRESS]', type=str, help='The IP address of the server (e.g. "192.168.1.1")')
    parser.add_argument("-p", "--port", metavar='[PORT]', type=int, help="Samba Server Hostname or IP Address",default=445)
    parser.add_argument("-l", "--list", metavar='[FILE_NAME]', help="List of ip addresses to scan", type=str)
    parser.add_argument("-oj", metavar='[FILE_NAME]', help="Output file in json", type=str)
    parser.add_argument("-d", "--debug", help="Debug Mode On", action="store_true")

    try:
        args = parser.parse_args()
    except Exception as e:
        print_error('Failed {}'.format(e))
        exit(-1)

    if(args.list is not None):
        target = read_file_ip(args.list)
    elif(args.target is not None):
        target = [args.target]
    else:
        print_error("Target is required (-t or -l) !")
        logging.info('Finished')
        exit(0)

    # logging.INFO
    if(args.debug):
        logging.basicConfig(filename='smb-audit.log', encoding='utf-8', level=logging.DEBUG,format='%(asctime)s - [%(levelname)s] - %(message)s', datefmt='%d/%m/%Y %I:%M:%S %p')
    else:
        logging.basicConfig(filename='smb-audit.log', encoding='utf-8', level=logging.INFO,format='%(asctime)s - [%(levelname)s] - %(message)s', datefmt='%d/%m/%Y %I:%M:%S %p')
        
    return [target,args.port,args.oj]


def output_file(file_path:str,data:dict)->None:
    with open(file_path, "w") as f:
        f.write(data)
        
def export_json(output_path, tab_info:dict)->None:
    json_object = json.dumps(tab_info, indent = 4)
    output_file(output_path,json_object)

def main(tab_ip_address:dict, port:int, oj:str)->None:
    tab_info = []
    for ip_address in tab_ip_address:
        if(port_check(ip_address, port)):
            tab_info_ip = {ip_address:[]}
            print_info("Target ip address:\t%s\n\n" % highlightBold(ip_address))

            is_anonymous,server_info = login_anonymous(ip_address, port)
            print_server_information(is_anonymous, server_info)

            tab_version = check_smb_version(ip_address, port)

            tab_sign_info = check_signing(ip_address, port, tab_version)

            tab_info_ip[ip_address].append(server_info)
            tab_info_ip[ip_address].append(tab_version)
            tab_info_ip[ip_address].append(tab_sign_info)

            tab_info.append(tab_info_ip)
            print("\n\n")
        else:
            print_error('The port {} is not open ({}) !'.format(port, ip_address))
    if(oj is not None):
        export_json(oj, tab_info)

if __name__ == '__main__':
    main_banner()
    tab_ip_address, port, path_output = manage_arg()

    logging.info('Started')
    main(tab_ip_address, port, path_output)
    logging.info('Finished')