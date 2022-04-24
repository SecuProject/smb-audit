from typing import Literal
from xmlrpc.client import boolean
from impacket.smbconnection import SMBConnection
from impacket import smb
from netaddr import IPNetwork
import argparse
import socket
import logging
import json
import struct
import re

NEGOTIATE_PROTOCOL_REQUEST = b'\x00\x00\x00\x85\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x40\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00'
SESSION_SETUP_REQUEST = b'\x00\x00\x00\x88\xffSMB\x73\x00\x00\x00\x00\x18\x07\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x40\x00\x0d\xff\x00\x88\x00\x04\x11\x0a\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x00\x00\x00\x4b\x00\x00\x00\x00\x00\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x30\x00\x20\x00\x32\x00\x31\x00\x39\x00\x35\x00\x00\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x30\x00\x20\x00\x35\x00\x2e\x00\x30\x00\x00\x00'
TREE_CONNECT_REQUEST = b'\x00\x00\x00\x60\xffSMB\x75\x00\x00\x00\x00\x18\x07\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x08\x40\x00\x04\xff\x00\x60\x00\x08\x00\x01\x00\x35\x00\x00\x5c\x00\x5c\x00\x31\x00\x39\x00\x32\x00\x2e\x00\x31\x00\x36\x00\x38\x00\x2e\x00\x31\x00\x37\x00\x35\x00\x2e\x00\x31\x00\x32\x00\x38\x00\x5c\x00\x49\x00\x50\x00\x43\x00\x24\x00\x00\x00\x3f\x3f\x3f\x3f\x3f\x00'
NAMED_PIPE_TRANS_REQUEST = b'\x00\x00\x00\x4a\xffSMB\x25\x00\x00\x00\x00\x18\x01\x28\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x8e\xa3\x01\x08\x52\x98\x10\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x4a\x00\x02\x00\x23\x00\x00\x00\x07\x00\x5c\x50\x49\x50\x45\x5c\x00'

# https://www.cyberciti.biz/faq/how-to-configure-samba-to-use-smbv2-and-disable-smbv1-on-linux-or-unix/
SMB2_DIALECT_002      = 0x0202
SMB2_DIALECT_21       = 0x0210
SMB2_DIALECT_30       = 0x0300
SMB2_DIALECT_302      = 0x0302  #SMB 3.0.2
SMB2_DIALECT_311      = 0x0311  #SMB 3.1.1

RECV_BUFFER           = 1024

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
def highlightBold(msg:str)->str:
    return bcolors.BOLD + msg + bcolors.ENDC
def highlight(msg:str,mode:bool)->str:
    if(mode):
        return highlightGreen(msg)
    else:
        return highlightRed(msg)

def print_error(message) -> None:
    format_msg = '[{}x{}] {}'.format(bcolors.FAIL,bcolors.ENDC,message)
    print(format_msg)
    logging.error(message)
def print_info(message) -> None:
    format_msg = '[{}i{}] {}'.format(bcolors.BOLD,bcolors.ENDC,message)
    print(format_msg)
    logging.info(message)
def print_title(message) -> None:
    format_msg = '\n[{}-{}] {}\n'.format(bcolors.WARNING,bcolors.ENDC, highlightBold(message))
    print(format_msg)


def get_samba_version(ip_address: str, port:int=445) -> list:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip_address, port))

    sock.send(NEGOTIATE_PROTOCOL_REQUEST)
    recv_smb(sock)

    sock.send(SESSION_SETUP_REQUEST)
    session_setup_response = sock.recv(RECV_BUFFER)
    if len(session_setup_response) >= 44:
        smb_version = session_setup_response[44:].decode('utf-8').replace("\x00","")
        version = re.findall(r'\d+', smb_version)
        samba_version = []
        if(len(version) == 5):
            samba_version.append(int(version[2]))
            samba_version.append(int(version[3]))
            samba_version.append(int(version[4]))
            print(f"Server version:\t\t\tSAMBA {version[2]}.{version[3]}.{version[4]}\n")
            return samba_version
    return []
def get_server_info(smb_client: SMBConnection) -> dict:
    server_info = {}

    server_info['domain']  = smb_client.getServerDomain()
    server_info['name']    = smb_client.getServerName()
    server_info['os']      = smb_client.getServerOS()

    server_info['OSBuild'] = smb_client.getServerOSBuild()
    server_info['OSMajor'] = smb_client.getServerOSMajor()
    server_info['OSMinor'] = smb_client.getServerOSMinor()
    
    server_info['isLinux'] = (
        server_info['os'] == 'Windows 6.1 Build 0' and 
        server_info['OSBuild'] == 0 and 
        server_info['OSMajor'] == 6 and
        server_info['OSMinor'] == 1)

    return server_info
def list_dir(smb_client: SMBConnection) -> list:
    share_list = []
    try:
        for share in smb_client.listShares():
            share_name = share['shi1_netname'][:-1]
            share_remark = share['shi1_remark'][:-1]
            share_list.append({"name":share_name,"desc":share_remark,"perm":[]})

            try:
                smb_client.listPath(share_name, '*')
                share_list['perm'].append('READ')
            except Exception:
                pass
            try:
                smb_client.createDirectory(share_name, "tempTest1337_445498456541")
                smb_client.deleteDirectory(share_name, "tempTest1337_445498456541")
                share_list['perm'].append('WRITE')
            except Exception:
                pass

    except Exception as e:
        logging.debug(e)
    return share_list
def login_anonymous(ip_address: str, port:int=445) -> dict:
    smb_client = SMBConnection('*SMBSERVER', ip_address, sess_port=port) # , preferredDialect=dialect
    is_anonymous = False
    share_list = ""

    try:
        smb_client.login('', '')
        share_list = list_dir(smb_client)
        smb_client.logoff()
        is_anonymous = True
    except Exception as e:
        logging.debug('Failed {}'.format(e))
    server_info = get_server_info(smb_client)
    return [is_anonymous,server_info,share_list]

def print_server_information(ip_address:str, is_anonymous:bool, server_info:dict, share_list:list) -> None:
    print_title("Server information")

    print("Ip address:\t%s" % highlightBold(ip_address))

    if(server_info['domain']):
        print('Server domain:\t%s' % server_info['domain'])
    if(server_info['name']):
        print('Server name: \t%s' % server_info['name'])
    if(server_info['os']):
        print('Server OS: \t%s' % server_info['os'])

    print("Guest login:\t",end="")
    if(not is_anonymous):
        print("%s" % highlight("Not allow",True))
    else: 
        print("%s" % highlight("Allow",False))
        if(share_list):
            print_title("Share drives")
            print("{0:<20} {1:<20} {2:25}\n".format("Share Name","Permission","Description"))
            for share in share_list:
                if(share['perm'] == []):
                    perm = highlightBold("None") # None
                    #perm = highlightRed(' '.join(["READ","WRITE"]))
                else:
                    perm = highlightRed(' '.join(share['perm']))
                print("{0:<20} {1:<28} {2:25}".format(share['name'], perm, share['desc']))

def recv_smb(sock:socket) -> bytes:
	nb, = struct.unpack(">I", sock.recv(4))
	return sock.recv(nb)
def check_ms17_010(ip_address:str,port:int= 445) -> boolean:
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((ip_address, port))
	sock.send(NEGOTIATE_PROTOCOL_REQUEST)

	negotiate_reply = recv_smb(sock)
	if len(negotiate_reply) < 32 or struct.unpack("<I", negotiate_reply[5:9])[0] != 0 :  # negotiate_reply[9:13]
		return False

	sock.send(SESSION_SETUP_REQUEST)
	session_setup_response = sock.recv(RECV_BUFFER)
	if len(session_setup_response) < 34:
		return False
	print(session_setup_response[44:].decode())

	user_id = session_setup_response[32:34]
 
	modified_tree_connect_request = list(TREE_CONNECT_REQUEST)
	modified_tree_connect_request[32] = user_id[0]
	modified_tree_connect_request[33] = user_id[1]
	modified_tree_connect_request =  bytes(modified_tree_connect_request)

	sock.send(modified_tree_connect_request)
	tree_connect_response = sock.recv(RECV_BUFFER)

	tree_id = tree_connect_response[28:30]
	modified_trans2_session_setup = list(NAMED_PIPE_TRANS_REQUEST)
	modified_trans2_session_setup[28] = tree_id[0]
	modified_trans2_session_setup[29] = tree_id[1]
	modified_trans2_session_setup[32] = user_id[0]
	modified_trans2_session_setup[33] = user_id[1]
	modified_trans2_session_setup = bytes(modified_trans2_session_setup)

	sock.send(modified_trans2_session_setup)
	final_response = sock.recv(RECV_BUFFER)
    
	result = final_response[9:13] == b"\x05\x02\x00\xc0"
	sock.close()
	return result
def check_smbghost(ip_address:str,port:int=445) -> boolean:
    payload = b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
    
    sock = socket.socket(socket.AF_INET)
    sock.connect((ip_address,  port ))
    sock.send(payload)
    res = recv_smb(sock)
    sock.close()
    
    return (res[68:70] != b"\x11\x03" or res[70:72] != b"\x02\x00")

def check_vuln(ip_address:str, port:int, server_info:dict, check_smb_version:dict)->dict:
    print_title("Check for exploit")
    exploit_list = {
        "exploit":{
            #"MS08-067"     :False,   # MS08-067      - SMBv1
            "cve_2012_182"  :False,   # CVE-2012-1182 - SAMBA   Samba 3.0.x - 3.6.3 (inclusive)
            #"ms10-054"     :False,   # ms10-054      - SMBv1
            #"ms10-061"     :False,   # ms10-061      - SMBv1
            "SambaCry"      :False,    # CVE-2017-7494 - SAMBA   Samba 3.x after 3.5.0 and 4.x before 4.4.14, 4.5.x before 4.5.10, and 4.6.x before 4.6.4
            "eternalblue"   :False,   # MS17-010      - SMBv1
            "smbghost"      :False    # CVE-2020-0796 - SMBv3
        }
    }
    if(check_smb_version["1"]["isEnable"] and server_info["isLinux"]):
        samba_version = get_samba_version(ip_address, port)

        # CVE-2012-1182 - Samba 3.0.x - 3.6.3 (inclusive)
        print(highlightBold("CVE-2012-1182") + ":\t\t\t",end="")
        if(samba_version[0] == 3 and (samba_version[1] < 6  or
        samba_version[1] == 6 and samba_version[2] <= 3)):
            print(highlightRed("Vulnerable"))
            exploit_list["exploit"]["cve_2012_182"] = True
        else:
            print(highlightGreen("Not vulnerable"))
        print(highlightBold("SambaCry") + " (CVE-2017-7494):\t",end="")
        # CVE-2017-7494 -  Samba 3.x after 3.5.0 and 4.x before 4.4.14, 4.5.x before 4.5.10, and 4.6.x before 4.6.4
        if(samba_version[0] == 3 and samba_version[1] > 5 or (samba_version[0] == 4 and (
            samba_version[1] < 4 or
            samba_version[1] == 4 and samba_version[2] < 14 or
            samba_version[1] == 5 and samba_version[2] < 10 or
            samba_version[1] == 6 and samba_version[2] < 4
        ))):
            print(highlightRed("Vulnerable"))
            exploit_list["exploit"]["SambaCry"] = True
        else:
            print(highlightGreen("Not vulnerable"))

    print(highlightBold("EternalBlue") + " (MS17-010):\t\t",end="")
    if(check_smb_version["1"]["isEnable"] and not server_info["isLinux"] and check_ms17_010(ip_address, port)):
        print(highlightRed("Vulnerable"))
        exploit_list["exploit"]["eternalblue"] = True
    else:
        print(highlightGreen("Not vulnerable"))
    
    print(highlightBold("SMBGhost") + " (CVE-2020-0796):\t",end="")
    if(check_smb_version["3.1.1"]["isEnable"] and check_smbghost(ip_address, port)):
        print(highlightRed("Vulnerable")+ "\tSMBv3: Compression (LZNT1) supported.")
        exploit_list["exploit"]["smbghost"] = True
    else:
        print(highlightGreen("Not vulnerable"))
    return exploit_list



def test_smb_version(ip_address:str, port:int=445,dialect:Literal=SMB2_DIALECT_311, debug=False):
    try:
        smb_client = SMBConnection('*SMBSERVER', ip_address, sess_port=port, preferredDialect=dialect)
        if isinstance(smb_client, SMBConnection):
            return True
    except Exception as e:
        logging.debug('Failed {}'.format(e))
    return False

def check_smb_version(ip_address:str, port:int=445) -> dict:
    print_title("Testing SMB versions")
    tab_version = {
        "1":{'diablect':smb.SMB_DIALECT,        'isEnable':False,'secure':False},
        "2.0":{'diablect':SMB2_DIALECT_002,     'isEnable':False,'secure':True},
        "2.1":{'diablect':SMB2_DIALECT_21,      'isEnable':False,'secure':True},
        "3.0":{'diablect':SMB2_DIALECT_30,      'isEnable':False,'secure':True},
        "3.0.2":{'diablect':SMB2_DIALECT_302,   'isEnable':False,'secure':True},
        "3.1.1":{'diablect':SMB2_DIALECT_311,   'isEnable':False,'secure':True}
    }

    for version in tab_version:
        print(highlightBold("SMB %5s" % version)+"\t",end="")
        tab_version[version]['isEnable'] = test_smb_version(ip_address,port,tab_version[version]['diablect'])
        if(tab_version[version]['isEnable']):
            print(highlight("offered",tab_version[version]['secure']))
        else:
            print(highlight("not offered",not tab_version[version]['secure']))
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
    print_title("Advance SMB information")

    tab_info = []
    for version in tab_version:
        if(tab_version[version]['isEnable'] and version != '1'):
            try:
                smb_client = SMBConnection('*SMBSERVER', ip_address, preferredDialect=tab_version[version]['diablect'], sess_port=port)
                if isinstance(smb_client, SMBConnection):
                    print("\n%s"% highlightBold("SMB "+version))
                    
                    smb_conn = smb_client._SMBConnection
                    smb_conn_con = smb_client._SMBConnection._Connection
                    tab_info_ver = {version:[]}
                    
                    dict_req_signing = handle_sign_info("Require Signing\t\t",'RequireSigning',smb_conn_con['RequireSigning'])
                    dict_req_sec_neg = handle_sign_info("Require Secure Negotiate",'RequireSecureNegotiate',smb_conn.RequireSecureNegotiate)
                    dict_req_msg_signing = handle_sign_info("Require Message Signing",'RequireMessageSigning',smb_conn.RequireMessageSigning)
                    
                    dict_cli_req_msg_signing = handle_sign_info("Client Require Message Signing",'ClientSecurityMode',smb_conn_con['ClientSecurityMode'])
                    dict_serv_req_msg_signing = handle_sign_info("Server Require Message Signing",'ServerSecurityMode',smb_conn_con['ServerSecurityMode'])

                    tab_info_ver[version].append(dict_req_signing)
                    tab_info_ver[version].append(dict_req_sec_neg)
                    tab_info_ver[version].append(dict_req_msg_signing)
                    tab_info_ver[version].append(dict_cli_req_msg_signing)
                    tab_info_ver[version].append(dict_serv_req_msg_signing)


                    cli_cap = get_capabilities(smb_conn._Connection['ClientCapabilities'])
                    serv_cap = get_capabilities(smb_conn._Connection['ServerCapabilities'])
                    print("Client Capabilities:   \t\t"+str(cli_cap))
                    print("Server Capabilities:   \t\t"+str(serv_cap))
                    print("Encryption Algorithm List:\t"+str(smb_conn.EncryptionAlgorithmList))

                    tab_info_ver[version].append({'ClientCapabilities':cli_cap})
                    tab_info_ver[version].append({'ServerCapabilities':serv_cap})
                    tab_info_ver[version].append({'EncryptionAlgorithmList':smb_conn.EncryptionAlgorithmList})
                    tab_info.append(tab_info_ver)
            except Exception as e:
                logging.error('Failed {}'.format(e))
    return tab_info
def port_check(ip_address:str, port:int):
   sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   try:
      sock.connect((ip_address, port))
      sock.shutdown(2)
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
    print('  By: SecuProject - Version: 0.0.1-Dev\n')

def manage_arg() -> str:
    parser = argparse.ArgumentParser(description='ssh-audit is a tool for SMB configuration auditing.', usage='%(prog)s [-t IP_ADDRESS|-l FILE_NAME] [-p PORT] [-d] [-oj FILE_NAME]')
    parser.version = 'smb-audit version: 0.0.2-Dev'
    parser.add_argument('-t','--target', metavar='[IP_ADDRESS]', type=str, help='The IP address/Range of the server (e.g. "192.168.1.1 or 192.168.1.0/24")')
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
        target = []
        for addr in IPNetwork(args.target):
            target.append(str(addr))
    else:
        print('[{}x{}] Target is required (-t or -l) !\n'.format(bcolors.FAIL,bcolors.ENDC))
        logging.info('Finished')
        exit(0)

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

            is_anonymous,server_info, share_list = login_anonymous(ip_address, port)
            print_server_information(ip_address, is_anonymous, server_info, share_list)

            tab_version = check_smb_version(ip_address, port)

            tab_sign_info = check_signing(ip_address, port, tab_version)
            
            exploit_list = check_vuln(ip_address,port, server_info,tab_version)


            tab_info_ip[ip_address].append({"Anonymous":is_anonymous})
            tab_info_ip[ip_address].append({"ShareList":share_list})
            tab_info_ip[ip_address].append(server_info)
            tab_info_ip[ip_address].append(tab_version)
            tab_info_ip[ip_address].append(tab_sign_info)
            tab_info_ip[ip_address].append(exploit_list)

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