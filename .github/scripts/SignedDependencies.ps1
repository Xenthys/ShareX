# Dependencies are the top-level prebuilt EXE/DLL files in the main output,
# never project-built ShareX* files, subdirectories, or NuGet's global store.
function Get-DependencyInventory([string]$OutputDirectory) {
    Get-ChildItem -LiteralPath $OutputDirectory -File | Where-Object {
        $_.Extension -in '.exe', '.dll' -and $_.Name -notlike 'ShareX*'
    } | Sort-Object Name | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; Hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
    }
}

function Assert-SignedFile([string]$Path, [string]$Publisher) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) { throw "Invalid signature: $Path ($($signature.Status))" }
    if ($Publisher -and $signature.SignerCertificate.Subject -cne $Publisher) { throw "Unexpected signing publisher: $Path" }
    return $signature.SignerCertificate.Subject
}

function Assert-SignedCopy([string]$Source, [string]$Signed, [string]$Publisher) {
    $null = Assert-SignedFile $Signed $Publisher
    if ((Get-PeContentHash $Source) -ne (Get-PeContentHash $Signed)) { throw "Signed content does not match original: $Source" }
}

function Prepare-SignedDependencies([string]$OutputDirectory, [string]$CacheDirectory, [string]$StageDirectory) {
    # The fresh ShareX signature anchors publisher identity to this Azure profile;
    # do not pin a rotating short-lived certificate thumbprint or trust a manifest.
    $publisher = Assert-SignedFile (Join-Path $OutputDirectory 'ShareX.exe')
    if (Test-Path -LiteralPath $StageDirectory) { throw "Signing stage must be fresh: $StageDirectory" }
    New-Item $StageDirectory -ItemType Directory -Force | Out-Null
    $pending = @()
    foreach ($entry in Get-DependencyInventory $OutputDirectory) {
        $source = Join-Path $OutputDirectory $entry.Name
        $signature = Get-AuthenticodeSignature -LiteralPath $source
        if ($signature.Status -eq 'Valid') { continue } # Preserve Microsoft's/other upstream signatures.
        if ($signature.Status -ne 'NotSigned') { throw "Invalid upstream signature: $source ($($signature.Status))" }
        $relative = Join-Path $entry.Hash $entry.Name
        $cached = Join-Path $CacheDirectory $relative
        if (Test-Path -LiteralPath $cached) {
            Assert-SignedCopy $source $cached $publisher
            Copy-Item -LiteralPath $cached -Destination $source -Force
        } else {
            # Reject malformed PE inputs before sending them to the signing service.
            $null = Get-PeContentHash $source
            $staged = Join-Path $StageDirectory $relative
            New-Item (Split-Path $staged) -ItemType Directory -Force | Out-Null
            Copy-Item -LiteralPath $source -Destination $staged
            $pending += $entry
        }
    }
    ConvertTo-Json -InputObject @($pending) | Set-Content (Join-Path $StageDirectory 'pending.json')
    return $pending.Count
}

function Complete-SignedDependencies([string]$OutputDirectory, [string]$CacheDirectory, [string]$StageDirectory) {
    $publisher = Assert-SignedFile (Join-Path $OutputDirectory 'ShareX.exe')
    foreach ($entry in (Get-Content (Join-Path $StageDirectory 'pending.json') -Raw | ConvertFrom-Json)) {
        $source = Join-Path $OutputDirectory $entry.Name
        if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $entry.Hash) { throw "Source changed while signing: $source" }
        $relative = Join-Path $entry.Hash $entry.Name
        $staged = Join-Path $StageDirectory $relative
        Assert-SignedCopy $source $staged $publisher
        $cached = Join-Path $CacheDirectory $relative
        New-Item (Split-Path $cached) -ItemType Directory -Force | Out-Null
        Copy-Item -LiteralPath $staged -Destination $cached -Force
        Copy-Item -LiteralPath $staged -Destination $source -Force
    }
}

# Only Authenticode bookkeeping may change: checksum, security directory and
# an aligned, terminal certificate table. Everything else (including overlays)
# is compared. Deliberately reject unusual layouts rather than weaken binding.
function Get-PeContentHash([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) { throw "Not a PE: $Path" }
    $pe = [BitConverter]::ToInt32($bytes, 60)
    if ($pe -lt 64 -or $pe + 24 -gt $bytes.Length -or [BitConverter]::ToUInt32($bytes, $pe) -ne 0x4550) { throw "Invalid PE: $Path" }
    $optional = $pe + 24
    $magic = [BitConverter]::ToUInt16($bytes, $optional)
    $directories = switch ($magic) { 0x10b { $optional + 96 }; 0x20b { $optional + 112 }; default { throw "Unknown PE type: $Path" } }
    $security = $directories + 32
    $optionalSize = [BitConverter]::ToUInt16($bytes, $pe + 20)
    if ($optional + $optionalSize -gt $bytes.Length -or $optional + $optionalSize -lt $security + 8 -or [BitConverter]::ToUInt32($bytes, $directories - 4) -lt 5) { throw "Invalid PE directories: $Path" }
    $offset = [BitConverter]::ToUInt32($bytes, $security)
    $size = [BitConverter]::ToUInt32($bytes, $security + 4)
    $length = $bytes.Length
    if ($offset -ne 0 -or $size -ne 0) {
        if ($offset % 8 -ne 0 -or $size -lt 8 -or $offset -lt $optional + $optionalSize -or [long]$offset + $size -ne $bytes.Length) { throw "Nonterminal or invalid PE certificate table: $Path" }
        $length = [int]$offset
    }
    [Array]::Clear($bytes, $optional + 64, 4)
    [Array]::Clear($bytes, $security, 8)
    # SignTool pads an unsigned file to an eight-byte boundary before appending.
    $normalized = [byte[]]::new(($length + 7) -band -8)
    [Array]::Copy($bytes, $normalized, $length)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($normalized))
}
