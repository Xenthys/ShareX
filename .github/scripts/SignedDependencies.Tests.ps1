$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/SignedDependencies.ps1"

function Assert($Condition, $Message) { if (-not $Condition) { throw $Message } }
function New-TestPe($Path, [byte]$Payload = 42, [switch]$Signed) {
    # Minimal PE fixture: not executable; tests comparison, not Windows trust.
    $bytes = [byte[]]::new($(if ($Signed) { 528 } else { 512 }))
    $bytes[0] = 0x4d; $bytes[1] = 0x5a
    [BitConverter]::GetBytes([int]128).CopyTo($bytes, 60)
    $bytes[128] = 0x50; $bytes[129] = 0x45
    [BitConverter]::GetBytes([uint16]240).CopyTo($bytes, 148)
    [BitConverter]::GetBytes([uint16]0x20b).CopyTo($bytes, 152)
    [BitConverter]::GetBytes([uint32]16).CopyTo($bytes, 260)
    $bytes[450] = $Payload
    if ($Signed) {
        [BitConverter]::GetBytes([uint32]512).CopyTo($bytes, 296)
        [BitConverter]::GetBytes([uint32]16).CopyTo($bytes, 300)
        $bytes[216] = 99 # checksum changes during signing
        $bytes[520] = 1
    }
    [IO.File]::WriteAllBytes($Path, $bytes)
}
$root = Join-Path ([IO.Path]::GetTempPath()) "signed-dependencies-tests-$([guid]::NewGuid())"
New-Item $root -ItemType Directory | Out-Null
try {
    New-TestPe "$root/original.dll"
    New-TestPe "$root/signed.dll" -Signed
    Assert ((Get-PeContentHash "$root/original.dll") -eq (Get-PeContentHash "$root/signed.dll")) 'Signing-only changes must compare equal'
    New-TestPe "$root/different.dll" -Payload 43 -Signed
    Assert ((Get-PeContentHash "$root/original.dll") -ne (Get-PeContentHash "$root/different.dll")) 'Changed code must not compare equal'
    Write-Host 'PASS: PE content comparison'

    function Get-AuthenticodeSignature($LiteralPath) {
        $b = [IO.File]::ReadAllBytes($LiteralPath)
        $status = if ($b.Length -eq 512) { 'NotSigned' } elseif ($b[520] -eq 3) { 'HashMismatch' } else { 'Valid' }
        $subject = if ($b.Length -gt 520 -and $b[520] -eq 2) { 'CN=Other' } else { 'CN=ShareX' }
        [pscustomobject]@{ Status = $status; SignerCertificate = [pscustomobject]@{ Subject = $subject } }
    }
    function Assert-Throws([scriptblock]$Action, $Message) {
        $threw = $false
        try { & $Action } catch { $threw = $true }
        Assert $threw $Message
    }
    New-Item "$root/output" -ItemType Directory | Out-Null
    New-TestPe "$root/output/ShareX.exe" -Signed
    New-TestPe "$root/output/ShareX.HelpersLib.dll"
    New-TestPe "$root/output/dependency.dll"
    New-TestPe "$root/output/vendor.dll" -Signed
    $vendor = [IO.File]::ReadAllBytes("$root/output/vendor.dll"); $vendor[520] = 2
    [IO.File]::WriteAllBytes("$root/output/vendor.dll", $vendor)
    $inventory = @(Get-DependencyInventory "$root/output")
    Assert ($inventory.Count -eq 2) 'Only third-party output binaries belong in the inventory'
    $count = Prepare-SignedDependencies "$root/output" "$root/cache" "$root/stage"
    Assert ($count -eq 1) 'Cold cache stages only unsigned dependencies, preserving upstream signatures'
    $pending = @(Get-ChildItem "$root/stage" -Recurse -Filter '*.dll')
    Assert ($pending.Count -eq 1) 'Exactly one signing request'
    New-TestPe $pending[0].FullName -Signed # Mock external Azure signer
    Complete-SignedDependencies "$root/output" "$root/cache" "$root/stage"
    Assert ((Get-AuthenticodeSignature "$root/output/dependency.dll").Status -eq 'Valid') 'New signatures copied back'
    Assert ((Get-AuthenticodeSignature "$root/output/vendor.dll").SignerCertificate.Subject -eq 'CN=Other') 'Upstream publisher preserved'
    Assert ((Get-AuthenticodeSignature "$root/output/ShareX.HelpersLib.dll").Status -eq 'NotSigned') 'Helper never caches or signs ShareX outputs'
    New-TestPe "$root/output/dependency.dll"
    Assert ((Prepare-SignedDependencies "$root/output" "$root/cache" "$root/stage2") -eq 0) 'Warm cache needs no signer'
    Complete-SignedDependencies "$root/output" "$root/cache" "$root/stage2"
    New-TestPe "$root/output/ffmpeg.exe" -Payload 44
    New-TestPe "$root/output/dependency.dll"
    Assert ((Prepare-SignedDependencies "$root/output" "$root/cache" "$root/mixed") -eq 1) 'A new dependency must not re-sign an unchanged cached dependency'
    $newFile = @(Get-ChildItem "$root/mixed" -Recurse -Filter '*.exe')[0].FullName
    New-TestPe $newFile -Payload 45 -Signed
    Assert-Throws { Complete-SignedDependencies "$root/output" "$root/cache" "$root/mixed" } 'New signer output with changed payload must fail'
    New-TestPe $newFile -Payload 44 -Signed
    $wrongPublisher = [IO.File]::ReadAllBytes($newFile); $wrongPublisher[520] = 2
    [IO.File]::WriteAllBytes($newFile, $wrongPublisher)
    Assert-Throws { Complete-SignedDependencies "$root/output" "$root/cache" "$root/mixed" } 'New signer output with wrong publisher must fail'
    New-TestPe $newFile -Payload 44 -Signed
    Complete-SignedDependencies "$root/output" "$root/cache" "$root/mixed"
    $badLayout = [IO.File]::ReadAllBytes($newFile)
    [BitConverter]::GetBytes([uint32]8).CopyTo($badLayout, 300)
    [IO.File]::WriteAllBytes("$root/nonterminal.exe", $badLayout)
    Assert-Throws { Get-PeContentHash "$root/nonterminal.exe" } 'Nonterminal certificate table must fail'
    New-TestPe "$root/output/dependency.dll" -Payload 43
    Assert ((Prepare-SignedDependencies "$root/output" "$root/cache" "$root/stage3") -eq 1) 'Changed dependency is a miss'
    New-TestPe "$root/output/dependency.dll"
    $cached = @(Get-ChildItem "$root/cache" -Recurse -Filter '*.dll')[0].FullName
    New-TestPe $cached -Payload 43 -Signed
    Assert-Throws { Prepare-SignedDependencies "$root/output" "$root/cache" "$root/bad-content" } 'Valid signature on unrelated bytes must fail'
    New-TestPe $cached -Signed
    $bad = [IO.File]::ReadAllBytes($cached); $bad[520] = 2; [IO.File]::WriteAllBytes($cached, $bad)
    Assert-Throws { Prepare-SignedDependencies "$root/output" "$root/cache" "$root/bad-publisher" } 'Unexpected cache publisher must fail'
    $bad[520] = 3; [IO.File]::WriteAllBytes($cached, $bad)
    Assert-Throws { Prepare-SignedDependencies "$root/output" "$root/cache" "$root/bad-signature" } 'Invalid cache signature must fail'
    Copy-Item $cached "$root/output/dependency.dll" -Force
    Assert-Throws { Prepare-SignedDependencies "$root/output" "$root/cache" "$root/bad-source" } 'Invalid upstream signature must fail'
    Write-Host 'PASS: cold/warm/changed cache, upstream preservation, scope, content/publisher/signature rejection'
} finally { Remove-Item $root -Recurse -Force }
