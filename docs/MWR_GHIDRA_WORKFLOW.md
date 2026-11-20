# Ghidra-assisted analysis workflow

## Scope and limits

Ghidra is an analysis aid for a decrypted memory image of the legacy 2016 game
build. It improves function, cross-reference and structure evidence, but it
cannot recover a different build's executable or prove every function's
identity. Candidates produced by this workflow are **not** verified mappings and
must not be written to `mapping.json` without independent confirmation.

The rule is stated plainly in every generated report:

> Ghidra cannot magically recover the missing 2019 executable or prove every
> function's identity. But it can substantially improve our analysis of the
> 2016 executable.

## Prerequisites

Ghidra 12.2 with a 64-bit Java 25 JDK. All paths are supplied by the caller:

```powershell
$env:GHIDRA_INSTALL  = '<ghidra-root>'
$env:JAVA_HOME       = '<java-install-root>'
$env:MWR_IMAGE       = '<path-to-decrypted_image.bin>'
$env:MWR_PROJECT_DIR = '<ghidra-project-dir>'
```

## Why BinaryLoader is required

The decrypted dump is laid out by RVA: section bytes begin at their
`VirtualAddress` offsets in the file, while its PE headers still contain the
original on-disk `PointerToRawData` values. The normal PE loader would map most
sections from the wrong offsets. The wrapper therefore uses:

- `-loader BinaryLoader`
- `-loader-baseAddr 0x140000000`
- `-processor x86:LE:64:default`
- `-cspec windows`

`PrepareMwrImage.java` runs before analysis. A raw binary import can leave the
program's image base at zero even though bytes were mapped at `0x140000000`, so
the scripts use the actual mapped base and never call `setImageBase`, which
would shift the address space. The pre-script rebuilds one memory block per
section from the PE section table using RVA offsets, applies section
permissions, creates functions from exact `.pdata` ranges, and applies recovered
labels from `name_tables.json` and `mapping.json` as `nt_`/`map_` prefixed
analysis aids.

## Running the analysis

```powershell
powershell -ExecutionPolicy Bypass -File tools\ghidra\run_headless.ps1
```

For a faster pass that decompiles only the first 2,000 functions:

```powershell
powershell -ExecutionPolicy Bypass -File tools\ghidra\run_headless.ps1 -MaxDecompile 2000
```

To re-run only the export step against an existing project:

```powershell
powershell -ExecutionPolicy Bypass -File tools\ghidra\run_headless.ps1 -SkipImport
```

The wrapper sets `JAVA_HOME`, logs to `build/resign/ghidra/headless.log` and
prints `GHIDRA_EXIT=<code>`. A zero exit code means the pipeline completed; it
does not validate any address.

## Generated artifacts

All artifacts are written under `build/resign/ghidra/`:

| Artifact | Contents |
| --- | --- |
| `metadata.json` | Schema, image base, language/compiler, counts and source image hash |
| `headless.log` | Full stdout/stderr of the run |
| `pdata.json` | Exact function ranges and unwind RVAs |
| `functions.json` | Function RVA/VA, recovered name, body range, signature, parameters, thunk/external flags |
| `symbols.json` | All Ghidra symbols, including `nt_`/`map_` labels applied by the pre-script |
| `data.json` | Defined data with RVA, type, size and default representation |
| `strings.json` | Defined strings with RVA and value |
| `xrefs.json` | Instruction-level references with source function, target, kind and operand |
| `function_refs.json` | Caller/callee edges with exact RVAs |
| `data_refs.json` | Function-to-data references with exact RVAs |
| `decompilation.json` | Decompiled C text plus success/error status per function |

## Cross-checking candidates

```powershell
python tools\integrate_ghidra_analysis.py
```

The integrator checks the exports against `memory_xref.json`, `call_graph.json`,
`name_tables.json`, `.pdata`, `unresolved.txt`, `worklist.txt` and `mapping.json`.
It writes `ghidra_integration.json` and `ghidra_candidate_report.md`.

The tool is read-only with respect to the retarget workflow. It never edits
`mapping.json`, `symbols.hpp`, `structs.hpp` or version checks. Labels copied from
`mapping.json` into the Ghidra project are excluded as circular evidence;
independent `nt_` labels, decompiled semantics, cross-references and raw-image
structure remain eligible.

## Verification

`tools/verify_scene_contract.py` performs an independent byte-level check of a
scene-rendering contract: exact prologues, `.pdata` starts, direct-call
displacements, ABI operand patterns, RIP-relative data references, caller edges
and native constants. It is read-only and prints `VERIFY_OK` when every check
passes.

## Validation boundary

Exports, candidate reports, builds and source audits are offline evidence.
Runtime acceptance requires launching the exact target client, loading a level
and exercising the affected paths. See `RUNTIME_VERIFICATION_1_15.md` for a
recorded example using a compatible baseline build.
