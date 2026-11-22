import struct, sys

# 读取 .ko 里 _printk 的符号值（用于校验 slide 是否匹配当前 boot）
path = sys.argv[1]
d = open(path, 'rb').read()
e_shoff = struct.unpack_from('<Q', d, 0x28)[0]
es = struct.unpack_from('<H', d, 0x3a)[0]
en = struct.unpack_from('<H', d, 0x3c)[0]
secs = []
for k in range(en):
    h = struct.unpack_from('<IIQQQQIIQQ', d, e_shoff + k * es)
    secs.append(dict(nameoff=h[0], typ=h[1], off=h[4], size=h[5], link=h[6]))
st = [s for s in secs if s['typ'] == 2][-1]
strt = secs[st['link']]['off']
found = None
for k in range(st['size'] // 24):
    nmv, info, oth, shndx, val, sz = struct.unpack_from('<IBBHQQ', d, st['off'] + k * 24)
    if not nmv:
        continue
    e = d.index(0, strt + nmv)
    n = d[strt + nmv:e].decode('utf-8', 'replace')
    if n == '_printk':
        found = val
        break
if found is None:
    print('NOTFOUND')
else:
    print('0x%x' % found)
