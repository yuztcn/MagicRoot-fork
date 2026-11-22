import struct, os, sys
BASE=r'C:\Users\14507\Documents\deepseek-harness\default-workspace'
src=sys.argv[1]; dst=sys.argv[2]
d=bytearray(open(src,'rb').read())
e_shoff=struct.unpack_from('<Q',d,0x28)[0]; es=struct.unpack_from('<H',d,0x3a)[0]
en=struct.unpack_from('<H',d,0x3c)[0]; si=struct.unpack_from('<H',d,0x3e)[0]
shstr=struct.unpack_from('<Q',d,e_shoff+si*es+0x18)[0]
targets={'.altinstructions','.rela.altinstructions','__bug_table','.rela__bug_table','__jump_table','.rela__jump_table'}
cleared=[]
def nm(x):
    s=shstr+x; e=d.index(0,s); return d[s:e].decode('utf-8','replace')
for k in range(en):
    base=e_shoff+k*es
    h=struct.unpack_from('<IIQQQQIIQQ',d,base)
    n=nm(h[0])
    if n in targets and h[5]>0:
        struct.pack_into('<Q',d,base+0x20,0)   # sh_size = 0
        cleared.append('%s(%d)'%(n,h[5]))
open(dst,'wb').write(d)
print('已清零:', ', '.join(cleared) if cleared else '(无)')
print('输出:', os.path.basename(dst), os.path.getsize(dst), '字节')
