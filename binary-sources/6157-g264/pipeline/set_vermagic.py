#!/usr/bin/env python3
"""Replace only the release token in a CGA module's .modinfo vermagic."""
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
GENERATOR = ROOT / "binary-sources/61157-g264/rebase_cga_module.py"
spec = importlib.util.spec_from_file_location("cga_vermagic_generator", GENERATOR)
if spec is None or spec.loader is None:
    raise RuntimeError(f"cannot load {GENERATOR}")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
kernel = sys.argv[3]
buffer = bytearray(source.read_bytes())
elf = module.Elf64(bytes(buffer))
module._patch_vermagic(buffer, elf, kernel)
destination.write_bytes(buffer)
print(f"vermagic={kernel} sha256={module.sha256(buffer)} output={destination}")
