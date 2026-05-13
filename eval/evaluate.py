"""evaluate.py — measure probdisasm output against function-symbol truth.

Ground truth: for each STT_FUNC symbol in the ELF, linearly disassemble the
[st_value, st_value + st_size) range with capstone. Every resulting
instruction address is treated as a true instruction start. With -O0 (and
even -O2 for small functions without jump tables / embedded data), this is
reliable on its own.

Usage:
    .venv/bin/python eval/evaluate.py <binary> <posteriors.csv>
"""

import argparse
import csv
import re
import subprocess
import sys

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


def extract_truth(binary_path: str) -> tuple[set[int], int, int]:
    """Return (truth_addrs, text_base, text_end)."""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    truth: set[int] = set()
    with open(binary_path, "rb") as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name(".text")
        if text is None:
            sys.exit(".text section not found")
        text_base = text["sh_addr"]
        text_bytes = text.data()
        text_end = text_base + len(text_bytes)

        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for sym in section.iter_symbols():
                if sym["st_info"]["type"] != "STT_FUNC":
                    continue
                size = sym["st_size"]
                addr = sym["st_value"]
                if size == 0 or addr < text_base or addr >= text_end:
                    continue
                end = min(addr + size, text_end)
                offset = addr - text_base
                bytes_slice = text_bytes[offset : offset + (end - addr)]
                for insn in md.disasm(bytes_slice, addr):
                    truth.add(insn.address)

    return truth, text_base, text_end


def extract_truth_objdump(
    binary_path: str, text_base: int, text_end: int
) -> set[int]:
    """Run `objdump -d` and pull every emitted instruction address within
    [text_base, text_end). With -O0 and no obfuscation this is essentially a
    complete instruction-boundary truth."""
    out = subprocess.check_output(
        ["objdump", "-d", binary_path], text=True, stderr=subprocess.DEVNULL
    )
    pat = re.compile(r"^\s+([0-9a-f]+):\s")
    addrs: set[int] = set()
    for line in out.splitlines():
        m = pat.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        if text_base <= addr < text_end:
            addrs.add(addr)
    return addrs


def load_posteriors(path: str) -> dict[int, float]:
    out: dict[int, float] = {}
    with open(path) as f:
        for row in csv.DictReader(f):
            out[int(row["address"])] = float(row["posterior"])
    return out


def pr_sweep(
    truth: set[int],
    posteriors: dict[int, float],
    thresholds: list[float],
    label: str = "",
) -> None:
    n_truth = len(truth)
    header = f"PR sweep vs {label}" if label else "PR sweep"
    print(f"\n{header}  (|truth|={n_truth})")
    print(
        f"{'tau':>8}  {'TP':>6}  {'FP':>6}  {'FN':>6}  "
        f"{'precision':>10}  {'recall':>8}  {'F1':>8}"
    )
    for tau in thresholds:
        tp = fp = 0
        for addr, p in posteriors.items():
            if p >= tau:
                if addr in truth:
                    tp += 1
                else:
                    fp += 1
        fn = n_truth - tp
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / n_truth if n_truth else 0.0
        f1 = (
            (2 * precision * recall / (precision + recall))
            if (precision + recall)
            else 0.0
        )
        print(
            f"{tau:>8.4f}  {tp:>6}  {fp:>6}  {fn:>6}  "
            f"{precision:>10.4f}  {recall:>8.4f}  {f1:>8.4f}"
        )


def histogram(posteriors: dict[int, float], bins: int = 10) -> None:
    counts = [0] * bins
    for p in posteriors.values():
        idx = min(int(p * bins), bins - 1)
        counts[idx] += 1
    width = max(counts)
    print("\nposterior histogram:")
    for i, c in enumerate(counts):
        lo = i / bins
        hi = (i + 1) / bins
        bar = "#" * (40 * c // width) if width else ""
        print(f"  [{lo:.1f}, {hi:.1f})  {c:>6}  {bar}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("posteriors")
    ap.add_argument(
        "--objdump",
        action="store_true",
        help="cross-check with objdump -d as a more complete truth source",
    )
    ap.add_argument(
        "--reclassify-tau",
        type=float,
        default=0.99,
        help="for objdump cross-check, threshold at which to compute "
        "how many symbol-truth FPs are confirmed by objdump",
    )
    args = ap.parse_args()

    sym_truth, text_base, text_end = extract_truth(args.binary)
    print(f"binary:    {args.binary}")
    print(
        f".text:     [0x{text_base:x}, 0x{text_end:x})  "
        f"({text_end - text_base} bytes)"
    )
    print(f"sym truth: {len(sym_truth)} instruction starts (STT_FUNC symbols)")

    posteriors = load_posteriors(args.posteriors)
    print(f"posterior: {len(posteriors)} rows from {args.posteriors}")

    thresholds = [0.99, 0.9, 0.75, 0.5, 0.25, 0.1, 0.05, 0.01, 0.001]
    pr_sweep(sym_truth, posteriors, thresholds, label="symbol-bounded truth")

    if args.objdump:
        obj_truth = extract_truth_objdump(args.binary, text_base, text_end)
        print(
            f"\nobjdump truth: {len(obj_truth)} instruction starts in .text"
        )
        print(
            f"  symbol truth ⊆ objdump truth: "
            f"{sym_truth.issubset(obj_truth)} "
            f"(|sym \\ obj| = {len(sym_truth - obj_truth)})"
        )
        pr_sweep(obj_truth, posteriors, thresholds, label="objdump truth")

        tau = args.reclassify_tau
        high_p = {a for a, p in posteriors.items() if p >= tau}
        sym_fps = high_p - sym_truth
        sym_fps_in_obj = sym_fps & obj_truth
        sym_fps_outside_obj = sym_fps - obj_truth
        print(
            f"\nFP reclassification at tau={tau}:"
            f"\n  symbol-truth FPs: {len(sym_fps)}"
            f"\n    confirmed as instructions by objdump: "
            f"{len(sym_fps_in_obj)}"
            f"\n    not in objdump either (likely true FP): "
            f"{len(sym_fps_outside_obj)}"
        )
        if sym_fps_outside_obj:
            sample = sorted(sym_fps_outside_obj)[:10]
            print(
                "    sample addrs not confirmed: "
                + ", ".join(f"0x{a:x}" for a in sample)
            )

    histogram(posteriors)


if __name__ == "__main__":
    main()
