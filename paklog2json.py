#!/usr/bin/python
import sys
import socket
import subprocess
import argparse
import os

""" Send udp data"""
def send_to_udp(data,ip,port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(data,(ip,port))

""" Send tcp data """
def send_to_tcp(data,ip,port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip,port))
    sock.send(data) 
    sock.close()

""" Check if program exists in system. """
def which(program):
    import os
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)
    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file
    return None

""" Check port if valid """
def check_port_range(port):
    if port in range(65536):
        return True
    else:
        print('Port '+str(port)+' is not in the valid range.Exiting')
        exit(1)

""" Main """
def exec_command(arg,prot,sp,spt):
    cmd = arg
    try :
        f = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        while True:
            line = f.stdout.readline()
            if prot == 'udp' :
                send_to_udp(line,sp,spt)
            else:
                send_to_tcp(line,sp,spt)
    except KeyboardInterrupt:
        print('Terminated by keyboard interrupt..BYE!')

""" Check if ip is valid """
def valid_ip4_address(ip):
    try:
        socket.inet_pton(socket.AF_INET,ip)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
             print('Socket error.Exiting.')
             exit(1)
        return address.count('.') == 3
    except socket.error:  # not a valid address
        print('Address:'+ip+' is not valid.Exiting.')
        exit(1)
    return True

""" Check if ipv6 is valid """      
def valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        print('Address:'+ip+' is not valid.Exiting.')
        exit(1)
    return True

if __name__ == '__main__':
    try:
        if os.geteuid() != 0:
            os.execvp("sudo", ["sudo"] + sys.argv)
    except OSError:
        print('OS error')
    """ Check if the programs that we need exist """
    for prog in ['dumpcap','tshark','jq']:
        if which(str(prog)):
            continue
        else:
            print('Program ' + prog + ' is not installed.Please install it and retry')
            exit(1)

    # Arguments parsing
    parser = argparse.ArgumentParser()
    parser.add_argument('-p','--listen_port',type=int,required=True)
    parser.add_argument('-proto' ,'--listen_protocol',choices=['tcp','udp'],required=True,type=str)
    parser.add_argument('-i','--interface',type=str)
    parser.add_argument('-d','--decode_as',help='Decode input stream as: etc syslog',type=str)
    parser.add_argument('-sip','--send_to_ip',type=str,required=True)
    parser.add_argument('-sport','--send_port',type=int,required=True)
    parser.add_argument('-sproto','--send_protocol',required=True,choices=['tcp','udp'],type=str)
    
    args=parser.parse_args()
    lport = args.listen_port
    check_port_range(lport)
    lprot = args.listen_protocol
    lint = args.interface
    dec = args.decode_as
    sdproto = args.send_protocol
    sdip = args.send_to_ip
    valid_ip4_address(sdip)
    sdpo = args.send_port
    check_port_range(sdpo)
    
    """ Compute the final value that will execute """
    if dec is None:
        tshark_ = ' tshark -r - -T ek -l '
    else:
        tshark_ = ' tshark -r - -d '''+lprot+'.port=='+str(lport)+','+dec+' -T ek -l '
    rest = '| grep -v index | jq -c \'.layers | {mtp3,sccp,gsm_map,gsm_sms}\''
    if lint is None:
        dcap = 'dumpcap -q -f \"'+lprot+' port '+str(lport)+'\" -w - |'+tshark_+rest
    else:
        dcap = 'dumpcap -q -i '+lint+' -f \"'+lprot+' port '+str(lport)+'\" -w - |'+tshark_+rest
    
    final_arg = dcap
    """ Send to execution """
    exec_command(final_arg,sdproto,sdip,sdpo)
