#!/usr/bin/env python3
"""Verify a scene-rendering contract against a decrypted MWR memory image.

This tool checks that a specific set of game functions and data globals match
exact bytes, unwind records, call displacements, ABI operand patterns, data
references and caller edges. It is read-only and prints PASS/FAIL per check.

Requires: pip install capstone
"""
import argparse
import json
import mmap
import os
import pathlib
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, CS_OP_REG
from capstone.x86_const import X86_REG_RIP

BASE = 0x140000000

PREPARE = 0x4B2410
FILTER = 0x4B39B0
RADIUS_GETTER = 0x400A80
SKIN = 0x4E7DD0
BUILDER = 0x4E7E50
BUILD_CALL = 0x4B2C6B
RADIUS_CALL = 0x4B3A35
PRIMARY_MOVSS = 0x4B3AFB
PRIMARY_CONSTANT = 0x14F672018

DOBJ_RECORDS = 0x151A54278
DOBJ_BANKS = 0x151A6A278
RIGID_RECORDS = 0x151A6B290
RIGID_BANKS = 0x151A9E290
SLOT_COUNTER = 0x151A4F668

failures = []


def check(condition, label, detail=""):
    print(("PASS  " if condition else "FAIL  ") + label + (f"  [{detail}]" if detail else ""))
    if not condition:
        failures.append(label)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=pathlib.Path,
                        default=pathlib.Path(os.environ.get("MWR_IMAGE", "decrypted_image.bin")),
                        help="path to the decrypted RVA-laid-out memory image")
    parser.add_argument("--ghidra-dir", type=pathlib.Path,
                        default=pathlib.Path(os.environ.get("MWR_GHIDRA_DIR", "build/resign/ghidra")),
                        help="directory containing pdata.json and function_refs.json")
    args = parser.parse_args()

    image = args.image
    ghidra = args.ghidra_dir

    pdata = json.loads((ghidra / "pdata.json").read_text(encoding="utf-8"))["entries"]
    frefs = json.loads((ghidra / "function_refs.json").read_text(encoding="utf-8"))["function_refs"]

    def pdata_begin(rva):
        return [x for x in pdata if int(x["begin"], 16) == rva]

    def callers(rva):
        return sorted({int(x["caller"], 16) for x in frefs if int(x["callee"], 16) == rva})

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    with image.open("rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
            def insns(start, end):
                return list(md.disasm(data[start:end], BASE + start))

            # Function starts must have real unwind/pdata coverage.
            for name, rva in (("prepare", PREPARE), ("filter", FILTER),
                              ("skin", SKIN), ("builder", BUILDER)):
                entries = pdata_begin(rva)
                check(bool(entries), f"{name} pdata start", str(entries[:1]))

            # Exact prologues used by the runtime contract checks.
            prepare_bytes = data[PREPARE:PREPARE + 32]
            expected = bytes.fromhex(
                "48894c2408555356574154415541564157488d6c24e14881ecc8000000 488b11".replace(" ", ""))
            check(prepare_bytes == expected, "prepare prologue bytes", prepare_bytes.hex(" "))

            skin_bytes = data[SKIN:SKIN + 9]
            expected_skin = bytes.fromhex("40534883ec208b4148")
            check(skin_bytes == expected_skin, "skin prologue bytes", skin_bytes.hex(" "))

            # Direct-call displacements must resolve to the independently derived targets.
            def direct_target(insn):
                if insn.mnemonic != "call" or not insn.op_str.startswith("0x"):
                    return None
                return int(insn.op_str, 16)

            build_i = [x for x in insns(BUILD_CALL, BUILD_CALL + 5) if x.address == BASE + BUILD_CALL]
            check(len(build_i) == 1 and direct_target(build_i[0]) == BASE + BUILDER,
                  "build call target", build_i[0].op_str if build_i else "no insn")

            radius_i = [x for x in insns(RADIUS_CALL, RADIUS_CALL + 5) if x.address == BASE + RADIUS_CALL]
            check(len(radius_i) == 1 and direct_target(radius_i[0]) == BASE + RADIUS_GETTER,
                  "radius call target", radius_i[0].op_str if radius_i else "no insn")

            # Native builder call gets exactly the ten source arguments via record pointer RCX=r15-0x30.
            call_window = {x.address: x for x in insns(0x4B2BB2, 0x4B2C70)}
            call_text = " | ".join(f"{x.mnemonic} {x.op_str}" for x in call_window.values())
            for token in ("lea rcx, [r15 - 0x30]", "mov rdx, rbx",
                          "mov r8, qword ptr [r15 - 0x20]", "lea r9, [r15 - 0x18]",
                          "mov qword ptr [rsp + 0x28], r10", "mov dword ptr [rsp + 0x40], eax",
                          "mov dword ptr [rsp + 0x48], r8d"):
                check(token in call_text, f"builder ABI: {token}")

            # Data bases are direct RIP-relative operands, not copied from old mappings.
            targets = {}
            for start, end, name in ((PREPARE, 0x4B2CC9, "prepare"), (FILTER, 0x4B3E3C, "filter")):
                for insn in insns(start, end):
                    for op in insn.operands:
                        if op.type == CS_OP_MEM and op.mem.base == X86_REG_RIP:
                            target = insn.address + insn.size + op.mem.disp
                            targets.setdefault(target, []).append((name, insn.address))
            for name, va in (("DObj records", DOBJ_RECORDS), ("DObj banks", DOBJ_BANKS),
                             ("rigid records", RIGID_RECORDS), ("rigid banks", RIGID_BANKS),
                             ("slot counter", SLOT_COUNTER)):
                check(va in targets, f"{name} RIP reference", str(targets.get(va, [])[:2]))

            # Runtime slot diagnostic reads the counter incremented by the native filter.
            slot_refs = set()
            for insn in insns(0x4B3C5A, 0x4B3C71):
                for op in insn.operands:
                    if op.type == CS_OP_MEM and op.mem.base == X86_REG_RIP:
                        slot_refs.add(insn.address + insn.size + op.mem.disp)
            check(SLOT_COUNTER in slot_refs, "filter increments slot counter",
                  " ".join(hex(x) for x in sorted(slot_refs)))

            # Four result bytes at RSP+A0 and rejected count in R11D feed the bridge.
            filter_text = " | ".join(f"{x.mnemonic} {x.op_str}" for x in insns(FILTER, 0x4B3E3C))
            check("lea r9, [rsp + 0xa0]" in filter_text, "filter result bytes at RSP+A0")
            check("inc r11d" in filter_text, "filter rejected count in R11D")
            for offset in ("0xb0", "0xb8", "0xc0"):
                check(f"qword ptr [rsp + {offset}]" in filter_text or
                      f"dword ptr [rsp + {offset}]" in filter_text,
                      f"filter colour arg at RSP+{offset}")

            movss_i = [x for x in insns(PRIMARY_MOVSS, PRIMARY_MOVSS + 8)
                       if x.address == BASE + PRIMARY_MOVSS]
            check(len(movss_i) == 1 and movss_i[0].size == 8 and movss_i[0].mnemonic == "movss",
                  "primary MOVSS is 8 bytes", movss_i[0].op_str if movss_i else "no insn")
            check(PRIMARY_CONSTANT in {insn.address + insn.size + op.mem.disp
                  for insn in movss_i for op in insn.operands
                  if op.type == CS_OP_MEM and op.mem.base == X86_REG_RIP},
                  "primary native constant", hex(PRIMARY_CONSTANT))

            # Call graphs anchor the function identities.
            pc = callers(PREPARE)
            fc = callers(FILTER)
            sc = callers(SKIN)
            check({0x5028B0, 0x502670}.issubset(pc), "prepare callers", [hex(x) for x in pc])
            check(0x1E4555 in fc, "filter caller", [hex(x) for x in fc])
            check(0x4B30A0 in sc, "skin callers", [hex(x) for x in sc])
            prepare_skin_i = [x for x in insns(0x4B26D6, 0x4B26E4) if x.address == BASE + 0x4B26DF]
            check(len(prepare_skin_i) == 1 and direct_target(prepare_skin_i[0]) == BASE + SKIN,
                  "prepare calls skin state machine",
                  prepare_skin_i[0].op_str if prepare_skin_i else "no insn")

            # Radius getter must be the only leaf reading XModel+0x220 with this exact body.
            getter_text = " | ".join(f"{x.mnemonic} {x.op_str}" for x in insns(RADIUS_GETTER, RADIUS_GETTER + 8))
            check(getter_text == "movss xmm0, dword ptr [rcx + 0x220]", "radius getter body", getter_text)

    print()
    if failures:
        print(f"VERIFY_FAILED count={len(failures)}")
        return 1
    print("VERIFY_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
