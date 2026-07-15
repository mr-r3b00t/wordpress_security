<#
.SYNOPSIS
    Tests a WordPress site for username/author enumeration leaks.

.DESCRIPTION
    Read-only reconnaissance against a site YOU OWN. Checks the enumeration
    vectors that feed username-permutation tooling:
      1. ?author=N  redirect leak (301/302 to /author/<slug>/)
      2. REST API   /wp-json/wp/v2/users
      3. REST index /wp-json  (occasional author leaks)
      4. User sitemap /wp-sitemap-users-1.xml
      5. oEmbed      /wp-json/oembed/1.0/embed?url=<post>  (author_name)

    No credentials, no login attempts, no writes. Just GETs.

.PARAMETER Url
    Base URL of the site, e.g. https://www.pwndefend.com

.PARAMETER MaxAuthorId
    Highest author ID to probe via ?author=N (default 10).

.PARAMETER DelayMs
    Minimum milliseconds between every request (default 750). Set 0 to disable.

.PARAMETER JitterMs
    Random 0..JitterMs ms added to each delay (default 250) so the traffic
    isn't a perfectly even, obviously-automated cadence.

.EXAMPLE
    .\Test-WPAuthorEnum.ps1 -Url https://www.pwndefend.com -MaxAuthorId 15

.EXAMPLE
    # Gentle: ~2s between requests
    .\Test-WPAuthorEnum.ps1 -Url https://www.pwndefend.com -DelayMs 2000 -JitterMs 500
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^https?://')]
    [string]$Url,

    [int]$MaxAuthorId = 10,

    # Minimum gap between requests, in milliseconds. Applied to EVERY request.
    [ValidateRange(0, 60000)]
    [int]$DelayMs = 750,

    # Random extra 0..JitterMs added to each delay so requests don't form a
    # perfectly even pattern (kinder to your logs, less bot-like).
    [ValidateRange(0, 10000)]
    [int]$JitterMs = 250
)

$ErrorActionPreference = 'Stop'
$base = $Url.TrimEnd('/')
$UA   = 'Test-WPAuthorEnum/1.0 (owner recon)'
$found = [System.Collections.Generic.HashSet[string]]::new()

# Rate-limit state: timestamp of the last request (null until first call)
$script:LastRequest = $null

# TLS 1.2 for older PowerShell 5.1 hosts
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

function Write-Result {
    param([string]$Vector, [string]$Status, [string]$Detail)
    $color = switch ($Status) {
        'LEAK'   { 'Red' }
        'CLOSED' { 'Green' }
        default  { 'Yellow' }
    }
    Write-Host ("[{0,-6}] " -f $Status) -ForegroundColor $color -NoNewline
    Write-Host ("{0,-22} {1}" -f $Vector, $Detail)
}

function Wait-RateLimit {
    # Sleep just long enough that consecutive requests are >= DelayMs (+jitter) apart.
    $target = $DelayMs
    if ($JitterMs -gt 0) { $target += Get-Random -Minimum 0 -Maximum ($JitterMs + 1) }
    if ($null -ne $script:LastRequest) {
        $elapsed = ([datetime]::UtcNow - $script:LastRequest).TotalMilliseconds
        $remaining = $target - $elapsed
        if ($remaining -gt 0) { Start-Sleep -Milliseconds ([int]$remaining) }
    }
    $script:LastRequest = [datetime]::UtcNow
}

function Invoke-Probe {
    param([string]$Uri, [switch]$NoRedirect)
    Wait-RateLimit
    $p = @{
        Uri             = $Uri
        UserAgent       = $UA
        TimeoutSec      = 20
        UseBasicParsing = $true
        Headers         = @{ 'Accept' = '*/*' }
    }
    if ($NoRedirect) { $p['MaximumRedirection'] = 0 }
    try {
        return Invoke-WebRequest @p
    } catch {
        # capture non-2xx responses (redirects when -NoRedirect, 401/403/404 etc.)
        if ($_.Exception.Response) { return $_.Exception.Response }
        throw
    }
}

Write-Host "`n=== WordPress Author Enumeration Check ===" -ForegroundColor Cyan
Write-Host "Target : $base"
Write-Host "Time   : $(Get-Date -Format o)"
Write-Host ("Rate   : {0} ms/request + 0-{1} ms jitter" -f $DelayMs, $JitterMs)`n

# ---------------------------------------------------------------------------
# 1. ?author=N  ->  redirect to /author/<slug>/
# ---------------------------------------------------------------------------
Write-Host "--- 1. ?author=N redirect leak ---" -ForegroundColor Cyan
for ($id = 1; $id -le $MaxAuthorId; $id++) {
    $probe = "$base/?author=$id"
    try {
        $r = Invoke-Probe -Uri $probe -NoRedirect
        $loc = $null
        # PS5.1 returns HttpWebResponse on redirect; PS7 may surface differently
        if ($r -is [System.Net.HttpWebResponse]) {
            $loc = $r.Headers['Location']
        } elseif ($r.Headers.Location) {
            $loc = $r.Headers.Location
        }
        if ($loc -and $loc -match '/author/([^/]+)/?') {
            $slug = $matches[1]
            [void]$found.Add($slug)
            Write-Result "?author=$id" "LEAK" "-> $slug"
        }
    } catch {
        Write-Verbose "author=$id : $($_.Exception.Message)"
    }
}
if ($found.Count -eq 0) { Write-Result "?author=N" "CLOSED" "no redirect leaked a slug" }

# ---------------------------------------------------------------------------
# 2. REST API /wp-json/wp/v2/users
# ---------------------------------------------------------------------------
Write-Host "`n--- 2. REST /wp-json/wp/v2/users ---" -ForegroundColor Cyan
try {
    $r = Invoke-Probe -Uri "$base/wp-json/wp/v2/users"
    $body = if ($r.Content) { $r.Content } else {
        $sr = New-Object IO.StreamReader($r.GetResponseStream()); $sr.ReadToEnd()
    }
    $users = $null
    try { $users = $body | ConvertFrom-Json } catch {}
    if ($users -and $users[0].slug) {
        foreach ($u in $users) {
            [void]$found.Add($u.slug)
            Write-Result "wp/v2/users" "LEAK" ("id={0} name='{1}' slug={2}" -f $u.id, $u.name, $u.slug)
        }
    } elseif ($body -match '"code"\s*:\s*"rest_') {
        Write-Result "wp/v2/users" "CLOSED" "endpoint restricted/disabled"
    } else {
        Write-Result "wp/v2/users" "INFO" "unexpected response (see -Verbose)"
        Write-Verbose $body
    }
} catch {
    Write-Result "wp/v2/users" "CLOSED" $_.Exception.Message
}

# ---------------------------------------------------------------------------
# 3. REST index /wp-json  (sometimes exposes author objects)
# ---------------------------------------------------------------------------
Write-Host "`n--- 3. REST index /wp-json ---" -ForegroundColor Cyan
try {
    $r = Invoke-Probe -Uri "$base/wp-json"
    $body = $r.Content
    if ($body -match '"author"|/wp/v2/users') {
        Write-Result "wp-json index" "INFO" "references author routes; inspect manually"
    } else {
        Write-Result "wp-json index" "CLOSED" "no obvious author data"
    }
} catch {
    Write-Result "wp-json index" "INFO" $_.Exception.Message
}

# ---------------------------------------------------------------------------
# 4. User sitemap (modern WP core)
# ---------------------------------------------------------------------------
Write-Host "`n--- 4. /wp-sitemap-users-1.xml ---" -ForegroundColor Cyan
try {
    $r = Invoke-Probe -Uri "$base/wp-sitemap-users-1.xml"
    $body = $r.Content
    $slugs = [regex]::Matches($body, '/author/([^/<]+)/?') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique
    if ($slugs) {
        foreach ($s in $slugs) { [void]$found.Add($s); Write-Result "user sitemap" "LEAK" "-> $s" }
    } else {
        Write-Result "user sitemap" "CLOSED" "not present or empty"
    }
} catch {
    Write-Result "user sitemap" "CLOSED" "not accessible"
}

# ---------------------------------------------------------------------------
# 5. oEmbed author_name leak (uses site homepage as the sample post)
# ---------------------------------------------------------------------------
Write-Host "`n--- 5. oEmbed author_name ---" -ForegroundColor Cyan
try {
    $embed = "$base/wp-json/oembed/1.0/embed?url=$([uri]::EscapeDataString($base))&format=json"
    $r = Invoke-Probe -Uri $embed
    $obj = $null; try { $obj = $r.Content | ConvertFrom-Json } catch {}
    if ($obj.author_name) {
        Write-Result "oEmbed" "INFO" ("author_name='{0}' (display name, feeds permutation)" -f $obj.author_name)
    } else {
        Write-Result "oEmbed" "CLOSED" "no author_name returned"
    }
} catch {
    Write-Result "oEmbed" "CLOSED" "not accessible"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
if ($found.Count -gt 0) {
    Write-Host "Leaked identifiers:" -ForegroundColor Red
    $found | Sort-Object | ForEach-Object { Write-Host "  - $_" }
    Write-Host "`nRemediation:"
    Write-Host "  * Block ?author=N (redirect to home or 403 before the /author/ redirect fires)"
    Write-Host "  * Restrict wp/v2/users to authenticated requests (rest_endpoints filter / security plugin)"
    Write-Host "  * Ensure login slug != display_name != author slug"
    Write-Host "  * Disable the user sitemap if not needed"
} else {
    Write-Host "No slugs leaked by the checks above." -ForegroundColor Green
    Write-Host "Note: absence of a leak here doesn't prove every path is closed -- re-run after any theme/plugin change."
}
Write-Host ""
