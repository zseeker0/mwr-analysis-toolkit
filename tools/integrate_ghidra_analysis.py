#!/usr/bin/env python3
"""Cross-check Ghidra exports with the existing MWR retarget artifacts.

This tool only produces reports. It never edits mapping.json, symbols.hpp,
structs.hpp, or version checks. A candidate is not a verified mapping.
"""
import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

BASE = 0x140000000

PRIORITIES = {
    "Dvar": ("Dvar_", "DVAR_"),
    "Cmd": ("Cmd_", "Cbuf_", "command_whitelist"),
    "DB": ("DB_", "Sys_IsDatabaseReady2", "SV_Loaded", "g_asset"),
    "Script": ("Scr_", "VM_", "SL_", "PMem_", "FindVariable", "GetVariable",
               "scr_", "g_script", "hks", "lua_", "Hashtable_Create", "cclosure_Create"),
}

DECL_RE = re.compile(
    r"WEAK\s+(?:game::)?symbol<(.+?)>\s*([A-Za-z_][A-Za-z0-9_]*)\s*\{\s*(0[xX][0-9A-Fa-f]+|\d+)",
    re.S,
)


def load_json(path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"WARN: could not read {path}: {exc}")
        return default


def hx(value):
    return f"0x{int(value):X}"


def parse_int(value):
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


def parse_symbols(path):
    text = path.read_text(encoding="utf-8")
    symbols = {}
    for match in DECL_RE.finditer(text):
        template, name, value = match.groups()
        symbols[name] = {
            "template": " ".join(template.split()),
            "rva": parse_int(value),
            "function": "(" in template,
        }
    return symbols


def load_lines(path):
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")]


def strip_prefix(name):
    # nt_ labels come from the independent static name tables. map_ labels are
    # copied from mapping.json by PrepareMwrImage.java and are therefore
    # circular; keep them prefixed so they cannot become candidate evidence.
    if name.startswith("nt_"):
        return name[3:]
    return name


def build_name_index(symbols_doc, functions_doc):
    index = defaultdict(set)
    for symbol in symbols_doc.get("symbols", []):
        name = strip_prefix(symbol.get("name", ""))
        if name and symbol.get("rva"):
            index[name].add(parse_int(symbol["rva"]))
    for fn in functions_doc.get("functions", []):
        name = strip_prefix(fn.get("name", ""))
        if name and fn.get("rva") and not name.startswith("FUN_"):
            index[name].add(parse_int(fn["rva"]))
    return index


def priority_for(symbol):
    for group, prefixes in PRIORITIES.items():
        if any(symbol.startswith(prefix) for prefix in prefixes):
            return group
    return None


def excerpt(code, symbol, limit=900):
    if not code:
        return ""
    lines = code.splitlines()
    needles = [symbol, "Dvar", "Cmd_", "DB_", "Scr_", "scr_", "0x58", "+ 8"]
    useful = [line for line in lines if any(n.lower() in line.lower() for n in needles)]
    selected = (useful or lines)[:18]
    text = "\n".join(selected)
    return text[:limit]


# The two helpers observed in the 2016 image that receive the dvar_type from
# Dvar_Register* wrappers. These are semantic anchors, not symbol names.
REGISTER_HELPER_CALLS = (
    (re.compile(r"\bFUN_1403c7410\s*\((?P<args>[^;]*)\)", re.I | re.S), 2),
    (re.compile(r"\bFUN_1403c7660\s*\((?P<args>[^;]*)\)", re.I | re.S), 3),
)


def register_helper_type(code):
    """Return the dvar_type constant passed to a shared 2016 register helper."""
    for pattern, argument_index in REGISTER_HELPER_CALLS:
        for match in pattern.finditer(code):
            args = [arg.strip() for arg in match.group("args").split(",")]
            if len(args) <= argument_index:
                continue
            token = args[argument_index]
            if re.fullmatch(r"\d+", token):
                return int(token)
    return None


def collect_evidence(symbol, decomp_by_rva):
    """Conservative candidate generation. Every item is review-only evidence."""
    candidates = defaultdict(list)

    def add(rva, kind, detail, score):
        try:
            value = parse_int(rva)
        except (TypeError, ValueError):
            return
        candidates[value].append({"kind": kind, "detail": detail, "score": score})

    for rva in state["ghidra_names"].get(symbol, ()):
        add(rva, "ghidra_symbol", "Ghidra symbol matches symbol name", 100)
    for rva in state["name_tables"].get(symbol, ()):
        add(rva, "name_table", "Recovered static name table anchor", 90)
    for rva, strings in state["string_refs"].items():
        for item in strings:
            value = item.get("string", "")
            if value == symbol:
                add(rva, "self_named_string", f"Function references its own name: {value}", 95)

    group = priority_for(symbol)
    if group == "Dvar":
        expectations = {
            "Dvar_RegisterBool": (0, "boolean type passed to shared register helper"),
            "Dvar_RegisterFloat": (1, "float/value type passed to shared register helper"),
            "Dvar_RegisterValue": (1, "value type passed to shared register helper"),
            "Dvar_RegisterVec2": (2, "vec2 type passed to shared register helper"),
            "Dvar_RegisterVec3": (3, "vec3 type passed to shared register helper"),
            "Dvar_RegisterVec4": (4, "vec4 type passed to shared register helper"),
            "Dvar_RegisterInt": (5, "integer type passed to shared register helper"),
            "Dvar_RegisterEnum": (6, "enumeration type passed to shared register helper"),
            "Dvar_RegisterString": (7, "string type passed to shared register helper"),
        }
        wanted = expectations.get(symbol)
        if wanted:
            type_value, reason = wanted
            for rva, record in decomp_by_rva.items():
                code = record.get("c", "")
                if not code:
                    continue
                if register_helper_type(code) == type_value:
                    add(rva, "dvar_type_to_register_helper", reason, 60)

    ranked = []
    for rva, evidence in candidates.items():
        if rva not in state["pdata_starts"]:
            evidence = [e for e in evidence if e["kind"] == "ghidra_symbol"]
            if not evidence:
                continue
        dedup = {}
        for item in evidence:
            key = (item["kind"], item["detail"])
            dedup[key] = item
        items = sorted(dedup.values(), key=lambda e: -e["score"])
        ranked.append({
            "rva": hx(rva),
            "va": hx(BASE + rva),
            "score": sum(e["score"] for e in items),
            "evidence": items,
            "decompilation_excerpt": excerpt(decomp_by_rva.get(hx(rva), {}).get("c", ""), symbol),
            "verification_status": "candidate_only",
        })
    ranked.sort(key=lambda c: (-c["score"], parse_int(c["rva"])))
    return ranked


def build_report(args, symbols):
    ghidra_dir = args.ghidra_dir
    functions_doc = load_json(ghidra_dir / "functions.json", {"functions": []})
    symbols_doc = load_json(ghidra_dir / "symbols.json", {"symbols": []})
    pdata_doc = load_json(ghidra_dir / "pdata.json", {"entries": []})
    decomp_doc = load_json(ghidra_dir / "decompilation.json", {"functions": []})
    xref_doc = load_json(ghidra_dir / "function_refs.json", {"function_refs": []})
    data_ref_doc = load_json(ghidra_dir / "data_refs.json", {"data_refs": []})

    decomp_by_rva = {r.get("rva"): r for r in decomp_doc.get("functions", [])}
    state["ghidra_names"] = build_name_index(symbols_doc, functions_doc)
    state["pdata_starts"] = {parse_int(e["begin"]) for e in pdata_doc.get("entries", [])}
    state["name_tables"] = {
        name: [parse_int(v) for v in values]
        for name, values in load_json(args.resign_dir / "name_tables.json", {}).items()
    }
    state["callers"] = defaultdict(set)
    state["callees"] = defaultdict(set)
    for edge in xref_doc.get("function_refs", []):
        caller = parse_int(edge["caller"])
        callee = parse_int(edge["callee"])
        state["callers"][callee].add(caller)
        state["callees"][caller].add(callee)

    state["string_refs"] = defaultdict(list)
    xref_index = load_json(args.resign_dir / "memory_xref.json", {"by_function": {}})
    for fn_rva, refs in xref_index.get("by_function", {}).items():
        state["string_refs"][parse_int(fn_rva)] = refs

    mapping = load_json(args.resign_dir / "mapping.json", {})
    worklist = load_lines(args.resign_dir / "worklist.txt")
    # mapping.json is the authoritative current state. unresolved.txt is a
    # historical snapshot from before the last three mappings were applied.
    unresolved = {name for name in worklist if name not in mapping}
    unresolved_functions = []
    unresolved_data = []
    for name in worklist:
        if name not in unresolved or name not in symbols:
            continue
        (unresolved_functions if symbols[name]["function"] else unresolved_data).append(name)

    priorities = {}
    for group in PRIORITIES:
        names = [name for name in unresolved_functions if priority_for(name) == group]
        priorities[group] = []
        for name in names:
            candidates = collect_evidence(name, decomp_by_rva)
            priorities[group].append({
                "symbol": name,
                "current_rva": hx(symbols[name]["rva"]),
                "candidates": candidates[:args.limit],
            })

    data_candidates = []
    for name in unresolved_data:
        candidates = []
        for rva in state["ghidra_names"].get(name, ()):
            candidates.append({"rva": hx(rva), "kind": "ghidra_symbol", "score": 100})
        for ref in data_ref_doc.get("data_refs", []):
            if ref.get("function") is None:
                continue
            if parse_int(ref["data"]) in state["name_tables"].get(name, ()):
                candidates.append({"rva": ref["data"], "kind": "data_xref", "score": 40})
        data_candidates.append({
            "symbol": name,
            "current_rva": hx(symbols[name]["rva"]),
            "candidates": candidates[:args.limit],
        })

    dvar_layout = {
        "declared_in_structs_hpp": {
            "hash_or_name": "0x0",
            "flags": "0x8",
            "type": "0xC",
        },
        "observed_in_2016_image": [
            {
                "offset": "0x8",
                "interpretation": "dvar_type",
                "evidence": "Dvar_SetCommand@0x3C5F80: cmp byte ptr [rax+8], 7 (string type); "
                            "0x3C5EC0: type 5/6; 0x3C5D90: type 0",
            },
            {
                "offset": "0x58",
                "interpretation": "dvar chain/next pointer",
                "evidence": "Dvar_FindMalleableVar@0x3C6710 reads [rax+0x58] while walking dvar entries",
            },
        ],
        "conclusion": "2016 offset 0x8 is type, while structs.hpp declares flags at 0x8 and type at 0xC. "
                      "This is a structure-layout finding only. The Dvar_Register* RVAs were verified "
                      "separately by the exact dvar_type each wrapper passes to the shared register "
                      "helper; do not change dvar_t or apply setter/value-string mappings from this "
                      "layout evidence alone.",
    }

    result = {
        "schema": "mwr-ghidra-integration-v1",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "ghidra_dir": str(ghidra_dir),
            "functions": len(functions_doc.get("functions", [])),
            "symbols": len(symbols_doc.get("symbols", [])),
            "pdata_entries": len(pdata_doc.get("entries", [])),
            "decompiled_functions": sum(1 for r in decomp_doc.get("functions", [])
                                        if r.get("success")),
            "function_refs": len(xref_doc.get("function_refs", [])),
            "data_refs": len(data_ref_doc.get("data_refs", [])),
        },
        "counts": {
            "mapped": len(mapping),
            "unresolved_functions": len(unresolved_functions),
            "unresolved_data": len(unresolved_data),
        },
        "warning": "Ghidra cannot magically recover the missing 2019 executable or prove every "
                   "function's identity. But it can substantially improve our analysis of the "
                   "2016 executable.",
        "priorities": priorities,
        "data_candidates": data_candidates,
        "dvar_layout": dvar_layout,
        "mapping_writes": "none; this tool is read-only with respect to the retarget workflow",
    }

    args.out_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.out_dir / "ghidra_integration.json"
    json_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    md_path = args.out_dir / "ghidra_candidate_report.md"
    md_path.write_text(render_markdown(result), encoding="utf-8")

    print(f"INTEGRATION_OK json={json_path} report={md_path}")
    print(f"functions={result['inputs']['functions']} decompiled={result['inputs']['decompiled_functions']} "
          f"unresolved_functions={len(unresolved_functions)} unresolved_data={len(unresolved_data)}")
    return 0


def render_markdown(result):
    lines = [
        "# Ghidra-assisted candidate report",
        "",
        f"Generated: {result['generated_utc']}",
        "",
        "> " + result["warning"],
        "",
        "All rows below are **candidates for manual review**. No mapping was applied by this tool.",
        "",
        "Evidence policy: `map_` labels copied from `mapping.json` into the Ghidra project are "
        "excluded as circular. `nt_` labels from the independent static name tables, decompiled "
        "semantics, function/data xrefs and raw-image structure are eligible.",
        "",
        "## Inputs",
        "",
        f"- Ghidra functions: {result['inputs']['functions']}",
        f"- Ghidra symbols: {result['inputs']['symbols']}",
        f"- .pdata entries: {result['inputs']['pdata_entries']}",
        f"- Decompiled functions: {result['inputs']['decompiled_functions']}",
        f"- Function call refs: {result['inputs']['function_refs']}",
        f"- Data refs: {result['inputs']['data_refs']}",
        f"- Current verified mappings: {result['counts']['mapped']}",
        f"- Unresolved functions: {result['counts']['unresolved_functions']}",
        f"- Unresolved data globals: {result['counts']['unresolved_data']}",
        "",
    ]
    for group, entries in result["priorities"].items():
        lines += [f"## {group}", ""]
        if not entries:
            lines += ["No unresolved symbols in this priority group.", ""]
            continue
        lines += ["| Symbol | Current address | Best candidate RVA | Score | Evidence |",
                  "|---|---:|---:|---:|---|"]
        for entry in entries:
            if not entry["candidates"]:
                lines.append(f"| {entry['symbol']} | {entry['current_rva']} | — | — | no independent candidate |")
                continue
            best = entry["candidates"][0]
            kinds = ", ".join(ev["kind"] for ev in best["evidence"])
            lines.append(f"| {entry['symbol']} | {entry['current_rva']} | {best['rva']} | "
                         f"{best['score']} | {kinds} |")
        lines.append("")

    lines += ["## Data globals", "",
              "| Symbol | Current address | Best candidate RVA | Evidence |",
              "|---|---:|---:|---|"]
    for entry in result["data_candidates"]:
        best = entry["candidates"][0] if entry["candidates"] else None
        if best is None:
            lines.append(f"| {entry['symbol']} | {entry['current_rva']} | — | no independent candidate |")
        else:
            kinds = ", ".join(ev["kind"] for ev in best["evidence"])
            lines.append(f"| {entry['symbol']} | {entry['current_rva']} | {best['rva']} | {kinds} |")
    lines += ["", "## dvar layout mismatch", "",
              "The 2016 executable uses `dvar_type` at offset `0x8`; `structs.hpp` declares "
              "`flags` at `0x8` and `type` at `0xC`. Evidence:", ""]
    for item in result["dvar_layout"]["observed_in_2016_image"]:
        lines.append(f"- `{item['offset']}` — {item['interpretation']}: {item['evidence']}")
    lines += ["", result["dvar_layout"]["conclusion"], "",
              "## Validation status", "",
              "Offline analysis only. No runtime evidence and no in-game compatibility claim.", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    repo = Path(__file__).resolve().parent.parent
    parser.add_argument("--ghidra-dir", type=Path, default=repo / "build" / "resign" / "ghidra")
    parser.add_argument("--resign-dir", type=Path, default=repo / "build" / "resign")
    parser.add_argument("--symbols", type=Path,
                        default=repo / "src" / "client" / "game" / "mwr" / "symbols.hpp")
    parser.add_argument("--out-dir", type=Path, default=repo / "build" / "resign" / "ghidra")
    parser.add_argument("--limit", type=int, default=8,
                        help="maximum candidates retained per symbol")
    args = parser.parse_args()

    global state
    state = {}
    symbols = parse_symbols(args.symbols)
    return build_report(args, symbols)


if __name__ == "__main__":
    raise SystemExit(main())
