"""Databases of different sizes for the QEMU heap test (docs/qemu.md) -> <out_dir>/cardpass/q<N>.kdbx."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import make_test_dbs as m

out = Path(sys.argv[1]) / "cardpass"
out.mkdir(parents=True, exist_ok=True)
m.OUT = out
for n in [int(x) for x in sys.argv[2:]]:
    kp = m.new_db()
    groups = [kp.add_group(kp.root_group, f"Group {i}") for i in range(10)]
    for i in range(n):
        kp.add_entry(groups[i % 10], f"Site {i:04d}", f"user{i}@example.com", f"pw-{i}-{m.rng.getrandbits(64):x}",
                     url=f"https://site{i}.example.com")
    m.save(kp, f"q{n:04d}.kdbx")
