i='kernel32.dll'
g='Name'
f='title Aphorist && mode con: cols=105 lines=35'
w=Exception
a='ProcessId'
X='PINK'
h='RED'
W=' '
U=bytes
Z='RESET'
O='0'
N='0x'
M=hex
J=int
R=print
I=type
L=None
K=range
H=''
G=len
F=True
D=str
C=False
import os,pymem as E,re,time as P,ctypes as S,sys as Y,time as P,random as r,hashlib as s
Q={h:'\x1b[91m','GREEN':'\x1b[92m','YELLOW':'\x1b[93m','BLUE':'\x1b[94m','MAGENTA':'\x1b[95m','CYAN':'\x1b[96m','GREY':'\x1b[90m',Z:'\x1b[0m',X:'\x1b[38;5;206m'}
b=f"""{Q[X]}

                 _                _     _   
     /\         | |              (_)   | |  
    /  \   _ __ | |__   ___  _ __ _ ___| |_ 
   / /\ \ | '_ \| '_ \ / _ \| '__| / __| __|
  / ____ \| |_) | | | | (_) | |  | \__ \ |_ 
 /_/    \_\ .__/|_| |_|\___/|_|  |_|___/\__|
          | |                               
          |_|                               

{Q[Z]}"""
def d():
	if Y.platform=='win32':os.system('cls')
	else:os.system('clear')
m=C
def B(*B):
	A=H
	for C in B:A=A+W+D(C)
	R(f"{Q[X]}Aphorist Client {Q[Z]}: {A}")
n=C
o=0
t=C
e=1
j=2
e=3
V=C
c=C
d()
os.system(f)
R(b)
d()
os.system(f)
R(b)
B('Please make sure you are in the Aphorist game.')
class k:
	def __init__(A,ProgramName=L):
		B=ProgramName;A.ProgramName=B;A.Pymem=E.Pymem();A.Addresses={};A.Handle=L;A.is64bit=C;A.ProcessID=L;A.PID=A.ProcessID;A.First=F
		if I(B)==D:A.Pymem=E.Pymem(B);A.Handle=A.Pymem.process_handle;A.is64bit=not E.process.is_64_bit(A.Handle);A.ProcessID=A.Pymem.process_id;A.PID=A.ProcessID
		elif I(B)==J:A.Pymem.open_process_from_id(B);A.Handle=A.Pymem.process_handle;A.is64bit=not E.process.is_64_bit(A.Handle);A.ProcessID=A.Pymem.process_id;A.PID=A.ProcessID
	def h2d(A,hz,bit=16):
		if I(hz)==J:return hz
		return J(hz,bit)
	def d2h(C,dc,UseAuto=L):
		B=UseAuto;A=dc
		if I(A)==D:return A
		if B:
			if B==32:A=M(A&2**32-1).replace(N,H)
			else:A=M(A&2**64-1).replace(N,H)
		elif abs(A)>4294967295:A=M(A&2**64-1).replace(N,H)
		else:A=M(A&2**32-1).replace(N,H)
		if G(A)>8:
			while G(A)<16:A=O+A
		if G(A)<8:
			while G(A)<8:A=O+A
		return A
	def PLAT(E,aob):
		A=aob
		if I(A)==U:return A
		C=bytearray(b'');A=A.replace(W,H);D=[]
		for B in K(0,G(A),2):D.append(A[B:B+2])
		for B in D:
			if'?'in B:C.extend(b'.')
			if'?'not in B:C.extend(re.escape(U.fromhex(B)))
		return U(C)
	def AOBSCANALL(A,AOB_HexArray,xreturn_multiple=C):return E.pattern.pattern_scan_all(A.Pymem.process_handle,A.PLAT(AOB_HexArray),return_multiple=xreturn_multiple)
	def gethexc(C,hex):
		hex=hex.replace(W,H);A=[]
		for B in K(0,G(hex),2):A.append(hex[B:B+2])
		return G(A)
	def hex2le(D,hex):
		A=hex.replace(W,H);B=[]
		if G(A)>8:
			while G(A)<16:A=O+A
			for C in K(0,G(A),2):B.append(A[C:C+2])
			B.reverse();return H.join(B)
		if G(A)<9:
			while G(A)<8:A=O+A
			for C in K(0,G(A),2):B.append(A[C:C+2])
			B.reverse();return H.join(B)
	def calcjmpop(B,des,cur):
		A=B.h2d(des)-B.h2d(cur)-5;A=M(A&2**32-1).replace(N,H)
		if G(A)%2!=0:A=O+D(A)
		return A
	def isProgramGameActive(A):
		try:A.Pymem.read_char(A.Pymem.base_address);return F
		except:return C
	def DRP(B,Address,is64Bit=L):
		C='little';A=Address;A=A
		if I(A)==D:A=B.h2d(A)
		if is64Bit:return J.from_bytes(B.Pymem.read_bytes(A,8),C)
		if B.is64bit:return J.from_bytes(B.Pymem.read_bytes(A,8),C)
		return J.from_bytes(B.Pymem.read_bytes(A,4),C)
	def isValidPointer(B,Address,is64Bit=L):
		A=Address
		try:
			if I(A)==D:A=B.h2d(A)
			B.Pymem.read_bytes(B.DRP(A,is64Bit),1);return F
		except:return C
	def GetModules(A):return list(A.Pymem.list_modules())
	def getAddressFromName(D,Address):
		A=Address
		if I(A)==J:return A
		E=0;F=0
		for C in D.GetModules():
			if C.name in A:E=C.lpBaseOfDll;F=D.h2d(A.replace(C.name+'+',H));G=E+F;return G
		B('Unable to find Address:',A);return A
	def getNameFromAddress(A,Address):
		B=Address;I=E.memory.virtual_query(A.Pymem.process_handle,B);D=I.BaseAddress;C=H;F=0
		for G in A.GetModules():
			if G.lpBaseOfDll==D:C=G.name;F=B-D;break
		if C==H:return B
		J=C+'+'+A.d2h(F);return J
	def getRawProcesses(C):
		B=[]
		for A in E.process.list_processes():B.append([A.cntThreads,A.cntUsage,A.dwFlags,A.dwSize,A.pcPriClassBase,A.szExeFile,A.th32DefaultHeapID,A.th32ModuleID,A.th32ParentProcessID,A.th32ProcessID])
		return B
	def SimpleGetProcesses(C):
		B=[]
		for A in C.getRawProcesses():B.append({g:A[5].decode(),'Threads':A[0],a:A[9]})
		return B
	def YieldForProgram(A,programName,AutoOpen=C,Limit=9999999):
		G=programName;I=0
		while F:
			if I>Limit:B('Yielded too long, failed!');return C
			J=A.SimpleGetProcesses()
			for H in J:
				if H[g]==G:
					B('Found '+G+' with Process ID: '+D(H[a]))
					if AutoOpen:A.Pymem.open_process_from_id(H[a]);A.ProgramName=G;A.Handle=A.Pymem.process_handle;A.is64bit=not E.process.is_64_bit(A.Handle);A.ProcessID=A.Pymem.process_id;A.PID=A.ProcessID;B('Successfully attached to '+D(G))
					return F
			if A.First:B("Waiting for the Program '"+G+"'")
			A.First=C;P.sleep(1);I+=1
	def ReadPointer(C,BaseAddress,Offsets_L2R,is64Bit=L):
		H=is64Bit;I=C.DRP(BaseAddress,H);E=Offsets_L2R;A=I
		if E==L or G(E)==0:return A
		J=0
		for F in E:
			try:R(C.d2h(I+F));R(C.d2h(F));A=C.DRP(A+F,H);J+=1;R(C.d2h(A))
			except:B('Failed to read Offset at Index: '+D(J));return A
		return A
	def GetMemoryInfo(C,Address,Handle=L):
		B=Handle;A=Address
		if B:return E.memory.virtual_query(B,A)
		else:return E.memory.virtual_query(C.Handle,A)
	def MemoryInfoToDictionary(B,MemoryInfo):A=MemoryInfo;return{'BaseAddress':A.BaseAddress,'AllocationBase':A.AllocationBase,'AllocationProtect':A.AllocationProtect,'RegionSize':A.RegionSize,'State':A.State,'Protect':A.Protect,'Type':A.Type}
	def SetProtection(B,Address,ProtectionType=64,Size=4,OldProtect=S.c_ulong(0)):A=OldProtect;E.ressources.kernel32.VirtualProtectEx(B.Pymem.process_handle,Address,Size,ProtectionType,S.byref(A));return A
	def ChangeProtection(A,Address,ProtectionType=64,Size=4,OldProtect=S.c_ulong(0)):return A.SetProtection(Address,ProtectionType,Size,OldProtect)
	def GetProtection(A,Address):return A.GetMemoryInfo(Address).Protect
	def KnowProtection(M,Protection):
		L='PAGE_WRITECOMBINE';K='PAGE_NOCACHE';J='PAGE_GUARD';I='PAGE_WRITECOPY';H='PAGE_READWRITE';G='PAGE_READONLY';F='PAGE_NOACCESS';E='PAGE_EXECUTE_WRITECOPY';D='PAGE_EXECUTE_READWRITE';C='PAGE_EXECUTE_READ';B='PAGE_EXECUTE';A=Protection
		if A==16:return B
		if A==32:return C
		if A==64:return D
		if A==128:return E
		if A==1:return F
		if A==2:return G
		if A==4:return H
		if A==8:return I
		if A==256:return J
		if A==512:return K
		if A==1024:return L
		if A in[B,'execute','e']:return 16
		if A in[C,'execute read','read execute','execute_read','read_execute','er','re']:return 32
		if A in[D,'execute read write','execute write read','write execute read','write read execute','read write execute','read execute write','erw','ewr','wre','wer','rew','rwe']:return 64
		if A in[E,'execute copy write','execute write copy','write execute copy','write copy execute','copy write execute','copy execute write','ecw','ewc','wce','wec','cew','cwe']:return 128
		if A in[F,'noaccess','na','n']:return 1
		if A in[G,'readonly','ro','r']:return 2
		if A in[H,'read write','write read','wr','rw']:return 4
		if A in[I,'write copy','copy write','wc','cw']:return 8
		if A in[J,'pg','guard','g']:return 256
		if A in[K,'nc','nocache']:return 512
		if A in[L,'write combine','combine write']:return 1024
		return A
	def Suspend(A,pid=L):
		B=S.WinDLL(i)
		if pid:B.DebugActiveProcess(pid)
		if A.PID:B.DebugActiveProcess(A.PID)
	def Resume(A,pid=L):
		B=S.WinDLL(i)
		if pid:B.DebugActiveProcessStop(pid)
		if A.PID:B.DebugActiveProcessStop(A.PID)
A=k()
while F:
	if A.YieldForProgram('RobloxPlayerBeta.exe',F,3):break
def A5(placeId):
	P=A.AOBSCANALL('62616E616E6173706C697473????????0C',F)
	for Q in P:
		J=Q;B('Result:'+D(A.d2h(J)));I=D(placeId);E=[]
		for L in K(1,16+1):
			if L<=G(I):
				C=M(ord(I[L-1])).replace(N,H)
				if G(C)==1:C=O+C
				E.append(C)
			else:E.append('00')
		C=M(G(I)).replace(N,H)
		if G(C)==1:C=O+C
		E.append(C);A.Pymem.write_bytes(J,U.fromhex(H.join(E)),A.gethexc(H.join(E)))
def u(ExpectedAddress):
	B=ExpectedAddress;C=A.Pymem.read_int(B+16)
	if C>15:return A.Pymem.read_string(A.DRP(B),C)
	return A.Pymem.read_string(B,C)
def v(Instance):B=A.DRP(A.DRP(Instance+24)+8);return u(B)
def p(Instance,Parent):H=Parent;F=Instance;A.Pymem.write_longlong(F+e,H);C=A.Pymem.allocate(1024);A.Pymem.write_longlong(C+0,C+64);J=A.Pymem.read_longlong(H+j);I=A.Pymem.read_longlong(J);K=A.Pymem.read_longlong(J+8);L=A.Pymem.read_bytes(I,I-K);A.Pymem.write_bytes(C+64,L,G(L));E=C+64+(K-I);A.Pymem.write_longlong(E,F);A.Pymem.write_longlong(E+8,A.Pymem.read_longlong(F+16));E=E+16;A.Pymem.write_longlong(C+8,E);A.Pymem.write_longlong(C+16,E);B('Set parent '+D(F)+' to '+D(H))
def l():
	A4='Waiting for game tool';A3='Got localplayer: ';global V;global c;R(H);B('Attempting to insert Aphorist')
	if not V:B('Attempting to attach')
	else:B('Attempting to insert')
	M=0;S=0;T=C;a=A.AOBSCANALL('506C6179657273??????????????????07000000000000000F',F)
	if not a:B('No results for AOBSCANALL, ending process.');P.sleep(3);Y.exit()
	for i in a:
		I=i
		if not I:B('Invalid results, ending process.');P.sleep(3);Y.exit()
		j=A.d2h(I);N=H
		for E in K(1,16+1):N=N+j[E-1:E]
		N=A.hex2le(N);k=C
		if t:A.Suspend()
		b=A.AOBSCANALL(N,F)
		if b:
			T=C
			for E in b:
				try:
					I=E
					for l in K(1,10+1):
						O=I-8*l
						if not A.isValidPointer(O):continue
						J=A.Pymem.read_longlong(O)
						if A.isValidPointer(J):
							O=J+8
							if not A.isValidPointer(O):continue
							J=A.Pymem.read_longlong(O)
							if A.Pymem.read_string(J)=='Players':
								if not k:k=F;M=I-8*l-24;S=I-M
								else:B('Got result: '+D(A.d2h(I)));M=I-8*l-24;S=I-M;T=F;break
					if T:break
				except:pass
			if T:break
		P.sleep(5)
	if t:A.Resume()
	B('Players: '+D(A.d2h(M)));B('Name offset: '+D(A.d2h(S)))
	if M==0:B('Failed to fetch Players Service.');return
	W=0
	for E in K(16,288+8,8):
		O=M+E
		if not A.isValidPointer(O):continue
		J=A.Pymem.read_longlong(O)
		if J!=0 and J%4==0:
			O=J+8
			if not A.isValidPointer(O):continue
			if A.Pymem.read_longlong(O)==J:W=E;break
	B('Parent offset: '+D(A.d2h(W)))
	if W==0:B('Failed to get Parent Offset.');return
	m=A.Pymem.read_longlong(M+W);B('DataModel: '+D(A.d2h(m)));n=0
	for E in K(16,512+8,8):
		J=A.Pymem.read_longlong(m+E)
		if J:
			try:
				d=A.Pymem.read_longlong(J);e=A.Pymem.read_longlong(J+8)
				if d and e:
					if e>d and e-d>1 and e-d<4096:n=E;break
			except:pass
	B('Children offset: '+D(A.d2h(n)))
	def A6(Instance):B=A.DRP(Instance+S,F);return B
	def x(Instance):A=A6(Instance);return u(A)
	def GetChildren(Instance):
		G=[];H=Instance
		if not H:return C
		D=A.DRP(H+n,F)
		if D==0:return[]
		I=A.DRP(D+8,F);J=16;E=A.DRP(D,F)
		for L in K(0,9000):
			if L==8999:B('Too many children, may cause issues.')
			if E==I:break
			G.append(A.Pymem.read_longlong(E));E+=J
		return G
	def A7(Instance):return A.DRP(Instance+W,F)
	def FindFirstChild(Instance,ChildName):
		B=GetChildren(Instance)
		for A in B:
			if x(A)==ChildName:return A
	def y(Instance,ClassName):
		B=GetChildren(Instance)
		for A in B:
			if v(A)==ClassName:return A
	class U:
		def __init__(A,address=0):B=address;A.Address=B;A.Self=B;A.Name=x(B);A.ClassName=v(B);A.Parent=A7(B)
		def getChildren(A):return GetChildren(A.Address)
		def findFirstChild(A,ChildName):return FindFirstChild(A.Address,ChildName)
		def findFirstClass(A,ChildClass):return y(A.Address,ChildClass)
		def GetChildren(A):return GetChildren(A.Address)
		def FindFirstChild(A,ChildName):return FindFirstChild(A.Address,ChildName)
		def FindFirstClass(A,ChildClass):return y(A.Address,ChildClass)
	M=U(M);AA=U(m);o=0
	for E in K(16,1536+4,4):
		J=A.Pymem.read_longlong(M.Self+E)
		if not A.isValidPointer(J):continue
		if A.Pymem.read_longlong(J+W)==M.Self:o=E;break
	B('Players.LocalPlayer offset: '+D(A.d2h(o)));p=U(A.DRP(M.Self+o));B(A3+D(A.d2h(p.Self)));B(A3+D(p.Name));z=U(p.FindFirstChild('Backpack'));B('Got backpack: '+D(A.d2h(z.Self)));A0=z.GetChildren()
	if G(A0)==0:
		if not V:B('Waiting for Aphorist game',C)
		else:B(A4,C)
		return
	A1=U(A0[0])
	if A1.Name=='ironbrew':
		if not V:B('Fetching Aphorist',C);A5(0);V=F;B('Fetched Aphorist! You can now teleport into your game.',C);return
		else:B(A4,C);return
	else:B('Fetched game tool!',C)
	try:A2=U(A1.findFirstClass('LocalScript'));B('Got tool script: '+D(A2.Name))
	except w as A8:B(f"There's been an issue fetching the LocalScript, re-attempting.\n      {Q[h]}{A8}{Q[Z]}",C);return
	X=L;a=A.AOBSCANALL('496E6A656374????????????????????06',F)
	if a==[]:B('Failed to get the LocalScript.',C);P.sleep(5);Y.exit()
	for i in a:
		I=i;j=A.d2h(I);N=H
		for E in K(1,16+1):N=N+j[E-1:E]
		N=A.hex2le(N);k=C;b=A.AOBSCANALL(N,F)
		if b:
			T=C
			for E in b:
				I=E;B('Result: '+D(A.d2h(I)))
				if A.Pymem.read_longlong(I-S+8)==I-S:X=I-S;T=F;break
		if T:break
	X=U(X);AB=A.Pymem.read_bytes(X.Self+256,336);P.sleep(5);f=20;q=b''
	for E in K(0,336,f):g=A.Pymem.read_bytes(X.Self+256+E,f);q+=g;P.sleep(r.uniform(.05,.1))
	A9=s.md5(A.Pymem.read_bytes(X.Self+256,336)).hexdigest()
	if A9!=s.md5(q).hexdigest():
		for E in K(0,336,f):g=q[E:E+f];A.Pymem.write_bytes(A2.Self+256+E,g,G(g));P.sleep(r.uniform(.05,.1))
	B('Attached Aphorist!');c=F;AC=L
while c==C:
	try:l()
	except TypeError as T:
		if not V:B(f"Waiting for the Aphorist game",C)
		else:B(f"Could not fetch LocalScript, re-attempting",C)
	except w as T:
		if'Array length must be'in D(T):B(f"You are in the process of a teleportation, waiting",C)
		elif'5'in D(T):B(f"Access denied to process",C);P.sleep(5);Y.exit()
		elif'299'in D(T):B(f"Only part of ReadProcessMemory / WriteProcessMemory was completed, retrying.",C)
		else:B(f"Error occured in attachment process, retrying\n     {Q[h]}{T}{Q[Z]}",C)
while c==F:0