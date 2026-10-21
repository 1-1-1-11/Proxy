"""Local-only helpers for the bounded proxy repair command."""
import ctypes,hashlib,http.client,io,json,os,pathlib,time
try:
    import ctypes.wintypes as w
except ImportError:  # Offline tests import this module off Windows. Win32 calls stay Windows-only.
    class w:
        DWORD = ctypes.c_uint32
        BOOL = ctypes.c_int

class Blob(ctypes.Structure):
    _fields_=[('size',w.DWORD),('data',ctypes.POINTER(ctypes.c_ubyte))]

def protect(data,decrypt=False):
    buf=ctypes.create_string_buffer(data)
    src=Blob(len(data),ctypes.cast(buf,ctypes.POINTER(ctypes.c_ubyte)));dst=Blob()
    crypt=ctypes.WinDLL('crypt32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    fn=crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    fn.argtypes=[ctypes.POINTER(Blob),ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,w.DWORD,ctypes.POINTER(Blob)];fn.restype=w.BOOL
    kernel.LocalFree.argtypes=[ctypes.c_void_p];kernel.LocalFree.restype=ctypes.c_void_p
    if not fn(ctypes.byref(src),None,None,None,None,1,ctypes.byref(dst)):raise ctypes.WinError(ctypes.get_last_error())
    try:return ctypes.string_at(dst.data,dst.size)
    finally:kernel.LocalFree(dst.data)

def atomic(path,data):
    path=pathlib.Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name(path.name+'.repair.tmp');tmp.write_bytes(data);os.replace(tmp,path)

class Changes:
    def __init__(self,folder):self.folder=pathlib.Path(folder);self.before={}
    def write(self,path,data):
        path=pathlib.Path(path);data=data.encode('utf-8') if isinstance(data,str) else data
        before=path.read_bytes() if path.exists() else None
        if before==data:return False
        if path not in self.before:
            self.before[path]=before
            self.folder.mkdir(parents=True,exist_ok=True)
            name=hashlib.sha256(str(path).encode()).hexdigest()[:16]+'.dpapi'
            atomic(self.folder/name,protect(before or b''))
            self.save_manifest()
        atomic(path,data);return True
    def save_manifest(self):
        entries=[{'path':str(p),'existed':b is not None,'file':hashlib.sha256(str(p).encode()).hexdigest()[:16]+'.dpapi'} for p,b in self.before.items()]
        atomic(self.folder/'manifest.json',json.dumps(entries,ensure_ascii=False,indent=2).encode('utf-8'))
    def restore_existing(self):
        for p,b in self.before.items():
            if b is not None:atomic(p,b)

def raw_api(path,method='GET',data=None):
    prefix='\\\\.\\pipe\\'
    matches=[n for n in os.listdir(prefix) if n.startswith('verge-mihomo-production-')]
    if len(matches)!=1:raise RuntimeError('Expected one managed Mihomo controller')
    for i in range(20):
        try:f=open(prefix+matches[0],'r+b',buffering=0);break
        except OSError:
            if i==19:raise
            time.sleep(.1)
    body=json.dumps(data,ensure_ascii=False).encode() if data is not None else b''
    class Sock:
        def makefile(self,*a,**kw):return io.BufferedReader(f)
    try:
        packet=(f'{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n').encode()+body
        offset=0
        while offset<len(packet):
            written=f.write(packet[offset:])
            if not written:raise OSError('Controller write closed')
            offset+=written
        r=http.client.HTTPResponse(Sock());r.begin();body=r.read()
        return r.status,json.loads(body) if body else None
    finally:f.close()

class SingleInstance:
    def __enter__(self):
        self.k=ctypes.WinDLL('kernel32',use_last_error=True)
        self.k.CreateMutexW.argtypes=[ctypes.c_void_p,ctypes.c_bool,ctypes.c_wchar_p];self.k.CreateMutexW.restype=ctypes.c_void_p
        self.h=self.k.CreateMutexW(None,False,'Local\\ClaudeProxyRepair-example')
        if not self.h or ctypes.get_last_error()==183:raise RuntimeError('Another repair is running')
        return self
    def __exit__(self,*args):
        self.k.CloseHandle.argtypes=[ctypes.c_void_p];self.k.CloseHandle(self.h)
