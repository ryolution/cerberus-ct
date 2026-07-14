param(
    [string]$UpstreamUrl = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json",
    [string]$OutputPath = "crates/cerberus-core/data/takeover_fingerprints.json",
    [switch]$Check
)

$ErrorActionPreference = "Stop"

function Normalize-Suffix {
    param([string]$Value)

    $suffix = $Value.Trim().TrimEnd(".").ToLowerInvariant()
    if ($suffix -eq "" -or $suffix -notmatch "^[a-z0-9.-]+$") {
        return $null
    }

    if ($suffix -match "^\d{1,3}(\.\d{1,3}){3}$") {
        return $null
    }

    if (-not $suffix.Contains(".")) {
        return $null
    }

    return $suffix
}

function First-Url {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    $match = [regex]::Match($Value, "https?://[^)\s]+")
    if ($match.Success) {
        return $match.Value
    }

    return $null
}

function New-Fingerprint {
    param(
        [string]$Provider,
        [string[]]$Suffixes,
        [AllowNull()][string]$DocumentationUrl,
        [string]$SourceUrl
    )

    $normalizedSuffixes = @(
        $Suffixes |
            ForEach-Object { Normalize-Suffix $_ } |
            Where-Object { $_ } |
            Sort-Object -Unique
    )

    if ($normalizedSuffixes.Count -eq 0) {
        return $null
    }

    [ordered]@{
        provider          = $Provider.Trim()
        cname_suffixes    = $normalizedSuffixes
        documentation_url = if ($DocumentationUrl) { $DocumentationUrl } else { $SourceUrl }
        source_url        = $SourceUrl
    }
}

function Merge-Fingerprint {
    param(
        [hashtable]$ByProvider,
        [object]$Fingerprint
    )

    if (-not $Fingerprint) {
        return
    }

    $key = $Fingerprint.provider.ToLowerInvariant()
    if (-not $ByProvider.ContainsKey($key)) {
        $ByProvider[$key] = $Fingerprint
        return
    }

    $existing = $ByProvider[$key]
    $existing.cname_suffixes = @(
        @($existing.cname_suffixes) + @($Fingerprint.cname_suffixes) |
            Sort-Object -Unique
    )

    if (-not $existing.documentation_url -and $Fingerprint.documentation_url) {
        $existing.documentation_url = $Fingerprint.documentation_url
    }
}

$sourceUrl = "https://github.com/EdOverflow/can-i-take-over-xyz"
$upstream = Invoke-RestMethod -Uri $UpstreamUrl
$byProvider = @{}

foreach ($item in $upstream) {
    if ($item.vulnerable -ne $true -or -not $item.cname -or $item.cname.Count -eq 0) {
        continue
    }

    $documentationUrl = First-Url $item.documentation
    if (-not $documentationUrl) {
        $documentationUrl = First-Url $item.discussion
    }

    $fingerprint = New-Fingerprint `
        -Provider $item.service `
        -Suffixes @($item.cname) `
        -DocumentationUrl $documentationUrl `
        -SourceUrl $sourceUrl

    Merge-Fingerprint -ByProvider $byProvider -Fingerprint $fingerprint
}

$curated = @(
    New-Fingerprint -Provider "GitHub Pages" -Suffixes @("github.io") -DocumentationUrl $sourceUrl -SourceUrl $sourceUrl
    New-Fingerprint -Provider "Heroku" -Suffixes @("herokuapp.com", "herokudns.com") -DocumentationUrl $sourceUrl -SourceUrl $sourceUrl
    New-Fingerprint -Provider "Netlify" -Suffixes @("netlify.app") -DocumentationUrl $sourceUrl -SourceUrl $sourceUrl
    New-Fingerprint -Provider "Vercel" -Suffixes @("vercel-dns.com", "vercel.app") -DocumentationUrl $sourceUrl -SourceUrl $sourceUrl
    New-Fingerprint -Provider "Shopify" -Suffixes @("myshopify.com") -DocumentationUrl $sourceUrl -SourceUrl $sourceUrl
    New-Fingerprint -Provider "Zendesk" -Suffixes @("zendesk.com") -DocumentationUrl $sourceUrl -SourceUrl $sourceUrl
    New-Fingerprint -Provider "Fastly" -Suffixes @("fastly.net") -DocumentationUrl $sourceUrl -SourceUrl $sourceUrl
)

foreach ($fingerprint in $curated) {
    Merge-Fingerprint -ByProvider $byProvider -Fingerprint $fingerprint
}

$records = @(
    $byProvider.Values |
        Sort-Object { $_.provider.ToLowerInvariant() }
)

$json = ($records | ConvertTo-Json -Depth 8) + [Environment]::NewLine

if ($Check) {
    $current = if (Test-Path $OutputPath) {
        Get-Content -Raw -Path $OutputPath
    } else {
        ""
    }

    if ($current -ne $json) {
        Write-Error "Takeover fingerprints are stale. Run scripts/update_takeover_fingerprints.ps1 and commit the updated data."
    }

    Write-Host "Takeover fingerprints are current."
    exit 0
}

$outputDirectory = Split-Path -Parent $OutputPath
if ($outputDirectory -and -not (Test-Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
}

Set-Content -Path $OutputPath -Value $json -NoNewline
Write-Host "Wrote $($records.Count) takeover fingerprints to $OutputPath."
