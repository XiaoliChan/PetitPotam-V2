from impacket import system_errors
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.dtypes import UUID, ULONG, WSTR, DWORD, NULL, BOOL, UCHAR, PCHAR, RPC_SID, LPWSTR, NDRPOINTERNULL

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
    align = 1
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
# Not working if system patched
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

# Useless in coerced authentication
class EfsRpcReadFileRaw(NDRCALL):
    opnum = 1
    structure = (
        ('hContext', EXIMPORT_CONTEXT_HANDLE),
    )
class EfsRpcReadFileRawResponse(NDRCALL):
    structure = (
        ('EfsOutPipe', EFS_EXIM_PIPE),
    )

# Useless in coerced authentication
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

# Useless in coerced authentication
class EfsRpcCloseRaw(NDRCALL):
    opnum = 3
    structure = (
        ('hContext', EXIMPORT_CONTEXT_HANDLE),
    )
class EfsRpcCloseRawResponse(NDRCALL):
    structure = (
    )

# Working !
class EfsRpcEncryptFileSrv(NDRCALL):
    opnum = 4
    structure = (
        ('FileName', WSTR),
    )
class EfsRpcEncryptFileSrvResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

# Working !
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

# Working !
class EfsRpcQueryUsersOnFile(NDRCALL):
    opnum = 6
    structure = (
        ('FileName', WSTR),
        
    )
class EfsRpcQueryUsersOnFileResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

# Working !
class EfsRpcQueryRecoveryAgents(NDRCALL):
    opnum = 7
    structure = (
        ('FileName', WSTR),
        
    )
class EfsRpcQueryRecoveryAgentsResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

# Working !
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

# Working !
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

# Working !
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

# Working !
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

# Working !
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

# Don't know how to make it work :(
class EfsRpcFileKeyInfoEx(NDRCALL):
    opnum = 16
    structure = (
        ('dwFileKeyInfoFlags', DWORD),
        ('Reserved', EFS_RPC_BLOB),
        ('FileName', WSTR),
        ('InfoClass', DWORD),
    )
class EfsRpcFileKeyInfoExResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

# Not working
class EfsRpcGetEncryptedFileMetadata(NDRCALL):
    opnum = 18
    structure = (
        ('FileName', WSTR),
    )
class EfsRpcGetEncryptedFileMetadataResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )   

# Don't know how to make it work :(
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

# Don't know how to make it work :(
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

# Not working
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