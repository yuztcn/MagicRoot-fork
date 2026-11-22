"""通用模块改名：自动检测 .modinfo 里现有的 name= 条目，等长或更短替换
用法: rename4.py <src> <dst> <newname>
"""
import struct, os, sys, re

src, dst, newname = sys.argv[1], sys.argv[2], sys.argv[3]
d = bytearray(open(src, 'rb').read())
e_shoff = struct.unpack_from('<Q', d, 0x28)[0]; es = struct.unpack_from('<H', d, 0x3a)[0]
en = struct.unpack_from('<H', d, 0x3c)[0]; si = struct.unpack_from('<H', d, 0x3e)[0]
secs = []
for k in range(en):
    h = struct.unpack_from('<IIQQQQIIQQ', d, e_shoff + k * es)
    secs.append(dict(nameoff=h[0], typ=h[1], off=h[4], size=h[5]))
shstr = secs[si]['off']
def nm(x):
    s = shstr + x; e = d.index(0, s); return d[s:e].decode('utf-8', 'replace')
names = {nm(s['nameoff']): s for s in secs}

mi = names['.modinfo']
base = mi['off']; size = mi['size']
blob = bytes(d[base:base + size])
m = re.search(rb'name=([^\x00]*)\x00', blob)
if not m:
    print('ERROR: .modinfo 中找不到 name= 条目'); sys.exit(1)
old = m.group(0)
oldname = m.group(1).decode()
seg = b'name=' + newname.encode() + b'\x00'
if len(seg) > len(old):
    print('ERROR: 新名 %s (%d) 比原名 %s (%d) 长，无法等长替换'
          % (newname, len(seg), oldname, len(old))); sys.exit(1)
seg = seg + b'\x00' * (len(old) - len(seg))
d[base + m.start():base + m.start() + len(old)] = seg

tm = names.get('.gnu.linkonce.this_module')
if tm:
    d[tm['off'] + 0x18:tm['off'] + 0x18 + 56] = newname.encode().ljust(56, b'\x00')

open(dst, 'wb').write(d)
print('改名 %s -> %s（%s -> %s，%d B）' % (os.path.basename(src), newname, oldname, newname, len(d)))
