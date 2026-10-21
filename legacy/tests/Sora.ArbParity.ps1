# Pins the legacy Client ARB files against drift (AUDIT-PARITY D3).
#
# Three checks, all against the files as they lie in the tree:
#   1. Every locale in Assets\l10n carries exactly the same set of
#      message keys as app_en.arb (the '@' metadata entries are not
#      message keys and legitimately exist only where a locale file
#      declares placeholders, so they are ignored as a set; a metadata
#      entry naming a key its own file does not carry is a failure).
#   2. languages.json and the app_*.arb files name the same locales,
#      so the language picker can never offer a missing resource.
#   3. Every ARB key the C# code asks Strings for exists in app_en.arb.
#      Keys reach Strings through literal indexer calls (text["..."]),
#      through ternary indexer calls (text[condition ? "..." : "..."] —
#      the tray toggle and the subscription-card toggles), through the
#      status ternary in MainForm.StateKey (both arms are keys; the
#      result is fed to text[...] there), through MakeButton("...", ...)
#      tags that ApplyText resolves, and through switch arms that
#      return a key (Strings.Error and the status rendering); every
#      shape is scanned in Client\*.cs.
#
# Runs on stock Windows PowerShell 5.1, manually:
#   powershell -File legacy\tests\Sora.ArbParity.ps1
# It is not wired into CI: no workflow in this repository invokes this
# script today, so until that connection is made as its own step, the
# pin holds only when someone runs it — the command above is the run.
# Exit code 0 and PASS lines on success; 1 with every failure listed.
param(
    [string]$ClientPath = (Join-Path $PSScriptRoot '..\Client')
)

$ErrorActionPreference = 'Stop'
$failures = New-Object System.Collections.Generic.List[string]

$l10n = Join-Path $ClientPath 'Assets\l10n'
$arbFiles = Get-ChildItem (Join-Path $l10n 'app_*.arb') | Sort-Object Name
if ($arbFiles.Count -lt 2) { throw "Expected the locale ARB files under $l10n." }

function Read-Arb([string]$Path) {
    return Get-Content $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

$keySets = @{}
foreach ($file in $arbFiles) {
    $arb = Read-Arb $file.FullName
    $names = $arb.PSObject.Properties.Name
    $keys = @($names | Where-Object { -not $_.StartsWith('@') } | Sort-Object)
    $keySets[$file.Name] = $keys
    foreach ($meta in $names | Where-Object { $_.StartsWith('@') -and -not $_.StartsWith('@@') }) {
        if ($keys -notcontains $meta.Substring(1)) {
            $failures.Add("$($file.Name): metadata $meta has no matching message key")
        }
    }
}

$referenceName = 'app_en.arb'
$reference = $keySets[$referenceName]
foreach ($file in $arbFiles) {
    $keys = $keySets[$file.Name]
    $missing = @($reference | Where-Object { $keys -notcontains $_ })
    $extra = @($keys | Where-Object { $reference -notcontains $_ })
    foreach ($key in $missing) { $failures.Add("$($file.Name): missing key $key") }
    foreach ($key in $extra) { $failures.Add("$($file.Name): extra key $key") }
}
Write-Host "ARB key sets: $($arbFiles.Count) locales, $($reference.Count) keys in $referenceName"

$languages = Get-Content (Join-Path $ClientPath 'Assets\languages.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$listed = @($languages | ForEach-Object { $_.code } | Sort-Object)
$onDisk = @($arbFiles | ForEach-Object { $_.BaseName.Substring(4) } | Sort-Object)
foreach ($code in $listed) {
    if ($onDisk -notcontains $code) { $failures.Add("languages.json lists $code but app_$code.arb is missing") }
}
foreach ($code in $onDisk) {
    if ($listed -notcontains $code) { $failures.Add("app_$code.arb exists but languages.json does not list $code") }
}
Write-Host "languages.json: $($listed.Count) locales listed, $($onDisk.Count) ARB files on disk"

$used = New-Object System.Collections.Generic.HashSet[string]
# The ternary shapes are deliberately narrow — a bare '?' ... ':' scan
# of every string pair would also catch non-key literals (the caret
# icon names "right"/"down" in SubscriptionCard) and turn this pin
# permanently red on strings that are not ARB keys at all.
$patterns = @(
    'text\["([A-Za-z][A-Za-z0-9]*)"\]',
    'text\[[^\]\r\n]*\?\s*"([A-Za-z][A-Za-z0-9]*)"\s*:\s*"([A-Za-z][A-Za-z0-9]*)"\]',
    '\?\s*"(state[A-Za-z][A-Za-z0-9]*)"\s*:\s*"(state[A-Za-z][A-Za-z0-9]*)"',
    'MakeButton\("([A-Za-z][A-Za-z0-9]*)"',
    '=>\s*"([a-z][A-Za-z0-9]*)"'
)
foreach ($source in Get-ChildItem (Join-Path $ClientPath '*.cs')) {
    $code = Get-Content $source.FullName -Raw -Encoding UTF8
    foreach ($pattern in $patterns) {
        foreach ($match in [regex]::Matches($code, $pattern)) {
            for ($group = 1; $group -lt $match.Groups.Count; $group++) {
                if ($match.Groups[$group].Success) { [void]$used.Add($match.Groups[$group].Value) }
            }
        }
    }
}
foreach ($key in $used) {
    if ($reference -notcontains $key) { $failures.Add("key used in Client code but missing from ARB: $key") }
}
Write-Host "Client code: $($used.Count) distinct keys requested from Strings"

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) { Write-Host "FAIL $failure" }
    exit 1
}
Write-Host "PASS ARB parity: identical key sets in every locale; every key used by the Client exists"
