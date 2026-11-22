"""offrelink3: 修正符号表追加（整表复制到文件尾）"""
import struct, os, sys
BASE=r'/root/work/cgabuild'
ko, out, slide = sys.argv[1], sys.argv[2], int(sys.argv[3],0)
SYMS_FILE=os.environ.get('CGA_ELF_SYMS', os.path.join(BASE,'staging','recon','elf_syms.txt'))
aliases={'__flush_icache_range':'caches_clean_inval_pou',
         '__flush_dcache_area':'dcache_clean_inval_poc'}
syms={}
for line in open(SYMS_FILE,encoding='utf-8',errors='replace'):
    p=line.split()
    if len(p)>=2 and p[1].startswith('0x'): syms.setdefault(p[0], int(p[1],16))

d=bytearray(open(ko,'rb').read())
e_shoff=struct.unpack_from('<Q',d,0x28)[0]; es=struct.unpack_from('<H',d,0x3a)[0]
en=struct.unpack_from('<H',d,0x3c)[0]; si=struct.unpack_from('<H',d,0x3e)[0]
secs=[]
for k in range(en):
    h=struct.unpack_from('<IIQQQQIIQQ',d,e_shoff+k*es)
    secs.append(dict(nameoff=h[0],typ=h[1],flags=h[2],addr=h[3],off=h[4],size=h[5],link=h[6],info=h[7]))
shstr=secs[si]['off']
def nm(x):
    s=shstr+x; e=d.index(0,s); return d[s:e].decode('utf-8','replace')
for s in secs: s['name']=nm(s['nameoff'])
idx={s['name']:i for i,s in enumerate(secs)}
PLT=idx['.text.ksustub']; IPLIT=idx['.text.ksustub']
SYMI=[i for i,s in enumerate(secs) if s['typ']==2][0]
symtab=secs[SYMI]; strtab=secs[symtab['link']]

# 1) 未定义 -> SHN_ABS
fixed=0; miss=[]
for k in range(symtab['size']//24):
    o=symtab['off']+k*24
    nmv,info2,other,shndx,val,sz=struct.unpack_from('<IBBHQQ',d,o)
    if shndx!=0 or nmv==0: continue
    e=d.index(0,strtab['off']+nmv); name=d[strtab['off']+nmv:e].decode('utf-8','replace')
    key=aliases.get(name,name); st=syms.get(key)
    if st is None: miss.append(name); continue
    struct.pack_into('<H',d,o+6,0xfff1)
    struct.pack_into('<Q',d,o+8,(st+slide)&0xFFFFFFFFFFFFFFFF)
    fixed+=1

# 2) 为远距离 CALL26 建跳板桩
stub_map={}; stub_list=[]; plt_used={PLT:0, IPLIT:0}; nrew=0
rels=[]
for s in secs:
    if s['typ']!=4: continue
    tgt=secs[s['info']]
    if not (tgt['flags']&0x2): continue
    isinit = tgt['name'].startswith('.init') or tgt['name'].startswith('.exit')
    for k in range(s['size']//24):
        o=s['off']+k*24
        r_off,r_info,r_add=struct.unpack_from('<QQq',d,o)
        if (r_info&0xffffffff) not in (283,282): continue
        sy=symtab['off']+(r_info>>32)*24
        nmv,i2,o2,shndx2,val2,sz2=struct.unpack_from('<IBBHQQ',d,sy)
        if shndx2!=0xfff1: continue
        addr=(val2+r_add)&0xFFFFFFFFFFFFFFFF
        key=(addr,isinit)
        if key not in stub_map:
            sec=IPLIT if isinit else PLT
            off=plt_used[sec]
            if off+16 > secs[sec]['size']: print('空间不足'); continue
            d[secs[sec]['off']+off:secs[sec]['off']+off+16]=struct.pack('<IIQ',0x58000050,0xd61f0200,addr)
            plt_used[sec]=off+16
            stub_map[key]=(sec,off); stub_list.append((sec,off))
        sec,off=stub_map[key]
        rels.append((o,sec,off)); nrew+=1

# 3) 整表复制 + 追加新符号
old_blob=bytes(d[symtab['off']:symtab['off']+symtab['size']])
base_count=symtab['size']//24
add=bytearray()
for (sec,off) in stub_list:
    add+=struct.pack('<IBBHQQ',0,0x03,0,sec,off,0)
new_off=len(d)
d+=old_blob+add
struct.pack_into('<Q',d,e_shoff+SYMI*es+0x18,new_off)
struct.pack_into('<Q',d,e_shoff+SYMI*es+0x20,len(old_blob)+len(add))
symtab['off']=new_off
# 重写重定位指向新符号
for o,sec,off in rels:
    si_new=base_count+stub_list.index((sec,off))
    struct.pack_into('<Q',d,o+8,(si_new<<32)|283)
    struct.pack_into('<q',d,o+16,0)

open(out,'wb').write(d)
print('slide=0x%x ABS=%d 缺失=%d 桩=%d 改写CALL26=%d 文件=%d'
      % (slide,fixed,len(miss),len(stub_list),nrew,len(d)))
if miss: print('  缺失:',miss[:6])
