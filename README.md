# MWR Analysis Toolkit

A small, read-only toolkit for finding reliable function addresses in a game
binary when source code is unavailable.

## The problem in plain terms

A VR modification for Call of Duty: Modern Warfare Remastered was written for
one build of the game. To make it work on a different build, internal functions
have to be located at new memory addresses. Guessing those addresses is not
safe: a wrong guess can send the game to a completely unrelated function and
crash it immediately.

One especially painful case was a function called `Cmd_AddCommandInternal`. The
older build placed it at `0x140343E00`. The newer build places it at
`0x140376A40`. A loader that used the old address crashed inside the wrong
function within seconds. That single mismatch is a good example of why every
address needs evidence.

## What this toolkit does

It does **not** patch the game and it does **not** change the project's address
table. It only produces evidence that a person can review.

| File | What it does, in plain terms |
| --- | --- |
| `tools/ghidra/PrepareMwrImage.java` | Teaches Ghidra how to read a decrypted memory dump. The dump is arranged by virtual address, but its PE header still points to old file offsets, so a normal import would read the wrong bytes. This script rebuilds the memory layout correctly and creates functions from the exception table. |
| `tools/ghidra/ExportMwrAnalysis.java` | Exports everything Ghidra learned as JSON: function boundaries, names, decompiled code, cross-references, strings and data locations. |
| `tools/ghidra/run_headless.ps1` | Runs the two scripts above without opening the Ghidra interface. All paths come from environment variables or command-line options, so nothing is tied to one machine. |
| `tools/integrate_ghidra_analysis.py` | Compares Ghidra's findings with earlier research and produces a shortlist of candidate addresses. It deliberately ignores labels copied from the project's own address table, because those would be circular evidence. |
| `tools/verify_scene_contract.py` | Checks a scene-rendering contract byte by byte: exact instruction sequences, call targets, argument passing, data references and caller relationships. Prints `VERIFY_OK` only when every check passes. |

## The most important rule

Ghidra cannot magically recover a missing executable or prove what every
function does. It can only improve the analysis of the binary that was actually
provided. Every candidate this toolkit produces is a **suggestion for a human**,
never an automatic mapping.

## How to use it

Set the paths for your machine:

```powershell
$env:GHIDRA_INSTALL  = '<ghidra-root>'
$env:JAVA_HOME       = '<java-install-root>'
$env:MWR_IMAGE       = '<path-to-decrypted_image.bin>'
$env:MWR_PROJECT_DIR = '<ghidra-project-dir>'
```

Run the analysis and export:

```powershell
powershell -ExecutionPolicy Bypass -File tools\ghidra\run_headless.ps1
```

Cross-check the results:

```powershell
python tools\integrate_ghidra_analysis.py
```

Verify the scene contract:

```powershell
python tools\verify_scene_contract.py --image <image> --ghidra-dir <export-dir>
```

The last command needs the Python `capstone` package:

```text
pip install capstone
```

## What was actually verified

- The headless export produced 37,940 functions and 37,936 successful
  decompilations, with 187,201 symbols and 574,224 cross-references.
- The scene-contract verifier passed every byte, unwind, call-displacement,
  ABI, data-reference and call-graph check.
- Candidate reports are produced, but no mapping is written by these tools.

A separate runtime check was performed with a build that matched the installed
2019/1.15 client. It loaded the `killhouse` map successfully with VR rendering
active and English language assets. Details and limits are in
[`docs/RUNTIME_VERIFICATION_1_15.md`](docs/RUNTIME_VERIFICATION_1_15.md).

That runtime result applies to the matching baseline build only. It is **not** a
compatibility claim for any 2016-derived build.

## Documentation

- [`docs/MWR_GHIDRA_WORKFLOW.md`](docs/MWR_GHIDRA_WORKFLOW.md) — technical
  details of the Ghidra pipeline and the generated artifacts.
- [`docs/RUNTIME_VERIFICATION_1_15.md`](docs/RUNTIME_VERIFICATION_1_15.md) —
  target identity, crash diagnosis and runtime evidence.
