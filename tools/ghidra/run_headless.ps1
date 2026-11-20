<#
.SYNOPSIS
Runs Ghidra headless analysis and export for a decrypted MWR memory image.

.DESCRIPTION
BinaryLoader is mandatory here: the decrypted dump is laid out by RVA, while its
PE header still contains stale on-disk raw pointers. The pre-script rebuilds
section blocks from VirtualAddress values and applies recovered labels; the
post-script exports functions, decompilation, xrefs and data references.

All paths are supplied by the caller so the script contains no machine-specific
locations. Set the GHIDRA_INSTALL, JAVA_HOME, MWR_IMAGE and MWR_PROJECT_DIR
environment variables, or pass the matching parameters explicitly.

.EXAMPLE
$env:GHIDRA_INSTALL = '<ghidra-root>'
$env:JAVA_HOME      = '<java-install-root>'
$env:MWR_IMAGE      = '<path-to-decrypted_image.bin>'
$env:MWR_PROJECT_DIR = '<ghidra-project-dir>'
powershell -ExecutionPolicy Bypass -File tools\ghidra\run_headless.ps1

.EXAMPLE
powershell -ExecutionPolicy Bypass -File tools\ghidra\run_headless.ps1 `
  -GhidraInstall '<ghidra-root>' -JavaHome '<java-root>' `
  -Image '<image>' -ProjectDir '<project-dir>' -MaxDecompile 2000
#>
[CmdletBinding()]
param(
    [string] $GhidraInstall = $env:GHIDRA_INSTALL,
    [string] $JavaHome      = $env:JAVA_HOME,
    [string] $ProjectDir    = $env:MWR_PROJECT_DIR,
    [string] $ProjectName   = 'MWR2016',
    [string] $Image         = $env:MWR_IMAGE,
    [string] $RepoRoot      = '',
    [string] $OutDir        = '',
    [ValidateSet('all', 'max', 'none')]
    [string] $DecompileMode = 'all',
    [int] $MaxDecompile     = 0,
    [int] $DecompileTimeout = 120,
    [switch] $SkipImport,
    [switch] $SkipPrepare
)

$ErrorActionPreference = 'Stop'

foreach ($required in @(
        @{Name = 'GhidraInstall'; Value = $GhidraInstall; Hint = 'set GHIDRA_INSTALL or pass -GhidraInstall'},
        @{Name = 'JavaHome';      Value = $JavaHome;      Hint = 'set JAVA_HOME or pass -JavaHome'},
        @{Name = 'ProjectDir';    Value = $ProjectDir;    Hint = 'set MWR_PROJECT_DIR or pass -ProjectDir'},
        @{Name = 'Image';         Value = $Image;         Hint = 'set MWR_IMAGE or pass -Image'})) {
    if ([string]::IsNullOrWhiteSpace($required.Value)) {
        throw "Missing required path $($required.Name): $($required.Hint)"
    }
}

$scriptPath = $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($scriptPath)) {
    throw 'Could not determine the wrapper script path.'
}
if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = (Resolve-Path (Join-Path (Split-Path -Parent $scriptPath) '..\..')).Path
}
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $RepoRoot 'build\resign\ghidra'
}

$analyzeHeadless = Join-Path $GhidraInstall 'support\analyzeHeadless.bat'
$scriptDir = Join-Path $RepoRoot 'tools\ghidra'
$logPath = Join-Path $OutDir 'headless.log'

if (-not (Test-Path $analyzeHeadless -PathType Leaf)) {
    throw "analyzeHeadless.bat not found: $analyzeHeadless"
}
if (-not (Test-Path (Join-Path $JavaHome 'bin\java.exe') -PathType Leaf)) {
    throw "java.exe not found under JAVA_HOME: $JavaHome"
}
if (-not (Test-Path $Image -PathType Leaf)) {
    throw "Decrypted image not found: $Image"
}

New-Item -ItemType Directory -Force -Path $ProjectDir | Out-Null
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$env:JAVA_HOME = $JavaHome
$env:PATH = "$JavaHome\bin;$env:PATH"

$headlessArgs = @($ProjectDir, $ProjectName)
if ($SkipImport) {
    $headlessArgs += @('-process', (Split-Path -Leaf $Image))
} else {
    $headlessArgs += @(
        '-import', $Image,
        '-loader', 'BinaryLoader',
        '-loader-baseAddr', '0x140000000',
        '-processor', 'x86:LE:64:default',
        '-cspec', 'windows',
        '-overwrite'
    )
}

$headlessArgs += @('-scriptPath', $scriptDir)
if (-not $SkipPrepare) {
    $headlessArgs += @('-preScript', 'PrepareMwrImage.java', $RepoRoot)
}

$postArgs = @(
    $RepoRoot,
    $OutDir,
    $Image,
    $DecompileMode,
    [string] $MaxDecompile,
    [string] $DecompileTimeout
)
$headlessArgs += @('-postScript', 'ExportMwrAnalysis.java') + $postArgs

Write-Host "JAVA_HOME=$env:JAVA_HOME"
Write-Host "GHIDRA=$analyzeHeadless"
Write-Host "ARGS=$($headlessArgs -join ' ')"
Write-Host "LOG=$logPath"

& $analyzeHeadless @headlessArgs 2>&1 | Tee-Object -FilePath $logPath
$exitCode = $LASTEXITCODE
Write-Host "GHIDRA_EXIT=$exitCode"
exit $exitCode
