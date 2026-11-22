#!/usr/bin/env python3
"""List AArch64 MOV{N,Z,K} constant materializations in an ELF text section.
Static analysis only; never loads or executes the input binary.
"""
from __future__ import annotations
import bisect
import struct
import sys
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile

MASK64 = (1 << 64) - 1

def mov_fields(word: int):
    for name, mask in (("movz", 0x52800000), ("movk", 0x72800000), ("movn", 0x12800000)):
        if word & 0x7F800000 == mask:
            sf = (word >> 31) & 1
            return name, sf, (word >> 21) & 3, (word >> 5) & 0xffff, word & 31
    return None

def main(path: Path) -> None:
    data = path.read_bytes()
    with path.open("rb") as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name(".text")
        text_bytes = text.data()
        text_addr = text["sh_addr"]
        text_offset = text["sh_offset"]
        symtab = elf.get_section_by_name(".symtab")
        funcs = []
        if symtab:
            for s in symtab.iter_symbols():
                if s["st_info"]["type"] == "STT_FUNC" and s["st_size"]:
                    funcs.append((s["st_value"], s["st_size"], s.name))
        funcs.sort()
        starts = [x[0] for x in funcs]
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        md.detail = True
        insns = list(md.disasm(text_bytes, text_addr))
    print(f"FILE {path} text={len(insns)}")
    active = {}
    for i, ins in enumerate(insns):
        off = ins.address - text_addr
        word = struct.unpack_from("<I", text_bytes, off)[0]
        fields = mov_fields(word)
        if fields:
            kind, sf, hw, imm, rd = fields
            bits = 64 if sf else 32
            mask = (1 << bits) - 1
            if kind == "movz":
                value = (imm << (16 * hw)) & mask
                active[rd] = {"start": i, "value": value, "count": 1, "bits": bits}
            elif kind == "movn":
                value = (~(imm << (16 * hw))) & mask
                active[rd] = {"start": i, "value": value, "count": 1, "bits": bits}
            elif rd in active and active[rd]["bits"] == bits:
                a = active[rd]
                a["value"] = (a["value"] & ~(0xffff << (16 * hw)) | (imm << (16 * hw))) & mask
                a["count"] += 1
            else:
                active.pop(rd, None)
            if rd in active:
                a = active[rd]
                start = insns[a["start"]]
                fi = bisect.bisect_right(starts, start.address) - 1
                fn = funcs[fi][2] if fi >= 0 and start.address < funcs[fi][0] + funcs[fi][1] else "?"
                value = a["value"]
                if value >= 0xffffff0000000000 or value in (0x108, 0x118, 0x838, 0x840, 0xb0, 0xb8):
                    file_off = text_offset + start.address - text_addr
                    print(f"{start.address:012x} file=0x{file_off:x} x{rd} n={a['count']} value=0x{value:x} {fn}")
        # Stop a sequence when a non-MOV instruction writes its destination register.
        if ins.mnemonic not in ("mov", "movk") and ins.operands:
            try:
                op = ins.operands[0]
                if op.type == 1:  # CS_OP_REG
                    active.pop(op.reg, None)
            except Exception:
                pass

if __name__ == "__main__":
    main(Path(sys.argv[1]))
