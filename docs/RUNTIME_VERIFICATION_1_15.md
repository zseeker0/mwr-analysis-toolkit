# Runtime verification on the 1.15 (2019) client

## Purpose

This record separates two things that are easy to confuse:

1. **Offline analysis** of a legacy 2016 memory image (the Ghidra workflow).
2. **Runtime behaviour** of a loader build against a specific game executable.

A build derived from 2016 addresses is not interchangeable with the 2019
client. This document records how that was demonstrated, and which build was
actually verified at runtime.

## Target identity

The installed 2019/1.15 single-player executable was verified before testing:

| Property | Value |
| --- | --- |
| File size | 20,213,128 bytes (`0x1346D88`) |
| PE timestamp | `0x5D374DBA` (2019-07-23 18:11:06 UTC) |
| PE format | x64, PE32+, 11 sections |
| Image size | `0x12654800` (308,627,456 bytes) |
| Entry RVA | `0x6D56E0` |
| SHA-256 | `3d23e86930668244d43a026552d5e1298a7c8cc63b82a54a7ad857e7b41f9190` |

## Why the 2016-derived build crashed

The 2016 retarget changed `Cmd_AddCommandInternal` from the 2019 address
`0x140376A40` to the 2016 address `0x140343E00`. Running that build against the
2019 executable produced an access violation at fault offset `0x343E06`, inside
that function. This is an address mismatch by construction, not a subtle runtime
bug.

## Verified build

The last clean pre-retarget baseline commit (`6e88fe0`) was built in an isolated
worktree. Its `image.hpp` already expects the 2019 identity above. The resulting
loader contained the 2019 `Cmd_AddCommandInternal` address and none of the 2016
addresses.

The build was deployed alongside its normal sidecar files and launched in
single-player mode.

## Load sequence

Startup is slow: roughly two minutes of CPU-bound unpacking before the main
window becomes interactive. An autosave-warning popup appears in campaign and
must be dismissed before console input works.

Language is selected by the game's locale folders. Renaming `zone\russian` to
`zone\_russian` makes the game load English assets; the log then shows English
paths only.

A map was loaded by opening the in-game console and entering `map killhouse`.
The diagnostic hotkey produced a support bundle with these status fields:

```
target_ready=yes environment="Singleplayer" scene_initialized=yes frontend=no
mapname="killhouse"
cl_ingame=unavailable
sv_running=yes
```

`cl_ingame` was unavailable because that symbol is unresolved in this build;
the other fields confirm the level was loaded, the scene initialized, and the
server was running. Console output also showed stereo eye targets ready, a
briefing-to-gameplay menu transition, and VR interaction hooks firing.

## Boundary of the claim

The verified result applies **only** to the baseline build against the 2019/1.15
client. It does not establish compatibility for the 2016-derived retarget, whose
offline analysis work remains separate and unverified at runtime.
