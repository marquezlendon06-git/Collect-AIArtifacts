#Requires -Version 5.1
<#
.SYNOPSIS
    AI Artifact Collector - standalone PowerShell triage script for IRFlow Timeline.

.DESCRIPTION
    Discovers and collects AI assistant conversation artifacts from a Windows user profile
    for forensic analysis in IRFlow Timeline (https://r3nzsec.github.io/irflow-timeline/).

    Supported tools:
      Claude Code CLI, Claude Desktop (Cowork / local-agent-mode),
      OpenAI Codex CLI, xAI Grok Build, ChatGPT Desktop (standalone + MS Store),
      Gemini CLI, Cursor (agent transcripts + IDE conversation DB),
      GitHub Copilot (VS Code products + CLI), Windsurf, Continue.dev

    Output mirrors the source directory structure so the collected folder can be loaded
    directly into IRFlow Timeline via Tools > Collect AI Artifacts > "Browse folder".

.PARAMETER OutputPath
    Destination folder for collected artifacts.
    Default: Desktop\AI-Artifacts-<yyyyMMdd-HHmmss>

.PARAMETER ProfilePath
    User profile root to collect from. Defaults to the current user's profile.
    Useful for offline/mounted images: e.g. -ProfilePath D:\MountedDisk\Users\victim

.PARAMETER AllUsers
    Scan every profile under C:\Users\ (or the parent of -ProfilePath if that flag
    points to one profile inside a Users tree).

.PARAMETER Compress
    Create a .zip archive of the output folder after collection.

.PARAMETER InventoryOnly
    Discover and report found artifact roots without copying any files.

.PARAMETER MaxFileSizeMB
    Skip individual files larger than this size in MB. Default: 200 MB.
    Oversized files are listed in the manifest with status "skipped-size".

.EXAMPLE
    .\Collect-AIArtifacts.ps1
    Collects from the current user; outputs to the Desktop.

.EXAMPLE
    .\Collect-AIArtifacts.ps1 -OutputPath C:\IRCase\AI -Compress
    Collects and zips to C:\IRCase\AI.zip.

.EXAMPLE
    .\Collect-AIArtifacts.ps1 -ProfilePath D:\Image\Users\victim -OutputPath C:\IRCase\AI
    Collects from a mounted image user profile.

.EXAMPLE
    .\Collect-AIArtifacts.ps1 -AllUsers -OutputPath C:\IRCase\AI
    Scans every profile under C:\Users\.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $OutputPath    = '',
    [string] $ProfilePath   = '',
    [switch] $AllUsers,
    [switch] $Compress,
    [switch] $InventoryOnly,
    [int]    $MaxFileSizeMB = 200
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# -- Globals ------------------------------------------------------------------
$script:MaxBytes     = [long]$MaxFileSizeMB * 1MB
$script:Collected    = 0
$script:SkippedSize  = 0
$script:Errors       = 0
$script:ManifestRows = [System.Collections.Generic.List[hashtable]]::new()
$script:StartTime    = Get-Date
$script:FoundRoots   = [System.Collections.Generic.List[hashtable]]::new()

# -- Console helpers ----------------------------------------------------------
function Write-Banner {
    Write-Host ""
    Write-Host "  +------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  |   IRFlow Timeline - AI Artifact Collector  v1.0      |" -ForegroundColor Cyan
    Write-Host "  +------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host ""
}
function Write-Section([string]$msg) {
    $pad = '-' * [Math]::Max(1, 54 - $msg.Length)
    Write-Host ("`n  -- $msg $pad") -ForegroundColor Cyan
}
function Write-Found([string]$msg) { Write-Host "  [+] $msg" -ForegroundColor Green }
function Write-Info([string]$msg)  { Write-Host "  [.] $msg" -ForegroundColor DarkGray }
function Write-Warn([string]$msg)  { Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Write-Miss([string]$msg)  { Write-Host "  [-] $msg" -ForegroundColor DarkGray }

# -- Profile path expansion ---------------------------------------------------
function Get-ProfileEnv([string]$ProfileRoot) {
    $r = [System.IO.Path]::GetFullPath($ProfileRoot)
    return @{
        USERPROFILE  = $r
        APPDATA      = Join-Path $r 'AppData\Roaming'
        LOCALAPPDATA = Join-Path $r 'AppData\Local'
    }
}

function Resolve-Profiles {
    $profiles = [System.Collections.Generic.List[string]]::new()
    if ($AllUsers) {
        $usersBase = if ($ProfilePath) {
            Split-Path ([System.IO.Path]::GetFullPath($ProfilePath)) -Parent
        } else {
            Split-Path $env:USERPROFILE -Parent
        }
        if (Test-Path $usersBase -PathType Container) {
            Get-ChildItem $usersBase -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notmatch '^(Public|Default|Default User|All Users)$' } |
            ForEach-Object { $profiles.Add($_.FullName) }
        }
    } elseif ($ProfilePath) {
        $profiles.Add([System.IO.Path]::GetFullPath($ProfilePath))
    } else {
        $profiles.Add($env:USERPROFILE)
    }
    return $profiles
}

# -- File copy with size guard ------------------------------------------------
function Copy-OneFile {
    param(
        [System.IO.FileInfo] $File,
        [string] $SourceRoot,
        [string] $DestRoot,
        [string] $Tool
    )
    if ($File.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint)) { return }
    if ($File.Length -gt $script:MaxBytes) {
        $mb = [Math]::Round($File.Length / 1MB, 1)
        Write-Warn "  Skipping large file ($mb MB): $($File.Name)"
        $script:SkippedSize++
        $script:ManifestRows.Add(@{
            tool     = $Tool; status = 'skipped-size'
            source   = $File.FullName; size = $File.Length
            modified = $File.LastWriteTimeUtc.ToString('o')
        })
        return
    }
    $rel     = $File.FullName.Substring([Math]::Min($SourceRoot.Length, $File.FullName.Length)).TrimStart('\','/')
    $dest    = Join-Path $DestRoot $rel
    $destDir = Split-Path $dest -Parent
    try {
        if (-not (Test-Path $destDir)) { New-Item $destDir -ItemType Directory -Force | Out-Null }
        Copy-Item $File.FullName $dest -Force -ErrorAction Stop
        $script:Collected++
        $script:ManifestRows.Add(@{
            tool     = $Tool; status = 'collected'
            source   = $File.FullName; dest = $dest
            size     = $File.Length
            modified = $File.LastWriteTimeUtc.ToString('o')
        })
    } catch {
        Write-Warn "  Error copying $($File.Name): $($_.Exception.Message)"
        $script:Errors++
        $script:ManifestRows.Add(@{
            tool   = $Tool; status = 'error'
            source = $File.FullName; error = $_.Exception.Message
        })
    }
}

function Collect-Tree {
    <#
    Recursively collect files matching wildcard patterns from SourceRoot into DestRoot.
    Skips symlinks / reparse points.
    #>
    param(
        [string]   $SourceRoot,
        [string]   $DestRoot,
        [string[]] $Include,
        [string[]] $Exclude  = @(),
        [string]   $Tool,
        [int]      $MaxDepth = 20
    )
    if (-not (Test-Path $SourceRoot -PathType Container)) { return 0 }
    $count = 0
    $stack = [System.Collections.Generic.Stack[object]]::new()
    $stack.Push(@{ path = $SourceRoot; depth = 0 })
    while ($stack.Count -gt 0) {
        $item  = $stack.Pop()
        $dir   = $item.path
        $depth = $item.depth
        $entries = $null
        try { $entries = Get-ChildItem $dir -ErrorAction Stop } catch { continue }
        foreach ($e in $entries) {
            if ($e.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint)) { continue }
            if ($e.PSIsContainer) {
                if ($depth -lt $MaxDepth) { $stack.Push(@{ path = $e.FullName; depth = $depth + 1 }) }
                continue
            }
            $match = $false
            foreach ($pat in $Include) {
                if ($e.Name -like $pat) { $match = $true; break }
            }
            if (-not $match) { continue }
            $skip = $false
            foreach ($pat in $Exclude) {
                if ($e.Name -like $pat) { $skip = $true; break }
            }
            if ($skip) { continue }
            if (-not $InventoryOnly) {
                Copy-OneFile -File $e -SourceRoot $SourceRoot -DestRoot $DestRoot -Tool $Tool
            }
            $count++
        }
    }
    return $count
}

# -- Per-tool collectors ------------------------------------------------------

function Collect-ClaudeCode([hashtable]$Env, [string]$OutBase) {
    $profileHome = $Env.USERPROFILE

    # CLI: ~/.claude/  (history.jsonl and/or projects/)
    $cliRoot = Join-Path $profileHome '.claude'
    if ((Test-Path (Join-Path $cliRoot 'history.jsonl')) -or
        (Test-Path (Join-Path $cliRoot 'projects'))) {
        Write-Found "Claude Code CLI: $cliRoot"
        $script:FoundRoots.Add(@{ tool = 'claude-code'; label = 'Claude Code CLI'; path = $cliRoot })
        $dest = Join-Path $OutBase 'claude-code-cli'
        $n = Collect-Tree -SourceRoot $cliRoot -DestRoot $dest `
            -Include @('*.jsonl', '*.json', '*.md') `
            -Exclude @('*.tmp') -Tool 'claude-code'
        Write-Info "  $n file(s) matched (CLI)"
    } else {
        Write-Miss 'Claude Code CLI (~/.claude/) - not found'
    }

    # Desktop: %APPDATA%\Claude\  (contains claude-code-sessions\ or local-agent-mode-sessions\)
    $desktopBase = Join-Path $Env.APPDATA 'Claude'
    $sessionDirs = @('claude-code-sessions', 'local-agent-mode-sessions')
    $hasDesktop  = $sessionDirs | Where-Object { Test-Path (Join-Path $desktopBase $_) }
    if ($hasDesktop) {
        Write-Found "Claude Desktop: $desktopBase"
        $script:FoundRoots.Add(@{ tool = 'claude-code'; label = 'Claude Desktop'; path = $desktopBase })
        $dest = Join-Path $OutBase 'claude-desktop'
        $n = Collect-Tree -SourceRoot $desktopBase -DestRoot $dest `
            -Include @('*.jsonl', '*.json', '*.md') `
            -Exclude @('*.tmp') -Tool 'claude-code'
        Write-Info "  $n file(s) matched (Desktop)"
    } else {
        Write-Miss 'Claude Desktop (%APPDATA%\Claude\) - not found'
    }
}

function Collect-Codex([hashtable]$Env, [string]$OutBase) {
    $codexHome = if ($env:CODEX_HOME) { $env:CODEX_HOME }
                 else                 { Join-Path $Env.USERPROFILE '.codex' }
    if (-not (Test-Path (Join-Path $codexHome 'history.jsonl')) -and
        -not (Test-Path (Join-Path $codexHome 'sessions'))) {
        Write-Miss 'OpenAI Codex (~/.codex/) - not found'; return
    }
    Write-Found "OpenAI Codex: $codexHome"
    $script:FoundRoots.Add(@{ tool = 'codex'; label = 'OpenAI Codex'; path = $codexHome })
    $dest = Join-Path $OutBase 'codex'
    $n = Collect-Tree -SourceRoot $codexHome -DestRoot $dest `
        -Include @('*.jsonl', '*.json', '*.md', '*.toml',
                   '*.sqlite', '*.sqlite-wal', '*.sqlite-shm',
                   '*.db', '*.db-wal', '*.db-shm') `
        -Exclude @('*.tmp', '*.bak') -Tool 'codex'
    Write-Info "  $n file(s) matched"
}

function Collect-GrokBuild([hashtable]$Env, [string]$OutBase) {
    $grokHome = if ($env:GROK_HOME) { $env:GROK_HOME }
                else                { Join-Path $Env.USERPROFILE '.grok' }
    if (-not (Test-Path (Join-Path $grokHome 'sessions'))) {
        Write-Miss 'xAI Grok Build (~/.grok/) - not found'; return
    }
    Write-Found "xAI Grok Build: $grokHome"
    $script:FoundRoots.Add(@{ tool = 'grok-build'; label = 'Grok Build'; path = $grokHome })
    $dest = Join-Path $OutBase 'grok-build'
    $n = Collect-Tree -SourceRoot $grokHome -DestRoot $dest `
        -Include @('*.jsonl', '*.json', '*.md', '*.yaml', '*.yml') `
        -Exclude @('auth.json', 'mcp_credentials.json', '*.tmp') `
        -Tool 'grok-build'
    Write-Info "  $n file(s) matched"
}

function Collect-GeminiCli([hashtable]$Env, [string]$OutBase) {
    $geminiHome = Join-Path $Env.USERPROFILE '.gemini'
    $tmpDir     = Join-Path $geminiHome 'tmp'
    if (-not (Test-Path $tmpDir)) {
        Write-Miss 'Gemini CLI (~/.gemini/) - not found'; return
    }
    Write-Found "Gemini CLI: $geminiHome"
    $script:FoundRoots.Add(@{ tool = 'gemini-cli'; label = 'Gemini CLI'; path = $geminiHome })
    $dest = Join-Path $OutBase 'gemini-cli'
    $n = Collect-Tree -SourceRoot $geminiHome -DestRoot $dest `
        -Include @('*.jsonl', '*.json', 'shell_history', 'logs.json') `
        -Tool 'gemini-cli'
    Write-Info "  $n file(s) matched"
}

function Collect-Cursor([hashtable]$Env, [string]$OutBase) {
    # Agent transcripts: ~/.cursor/projects/
    $cursorHome = if ($env:CURSOR_AGENT_HOME) { $env:CURSOR_AGENT_HOME }
                  elseif ($env:CURSOR_HOME)    { $env:CURSOR_HOME }
                  else                         { Join-Path $Env.USERPROFILE '.cursor' }
    if (Test-Path (Join-Path $cursorHome 'projects')) {
        Write-Found "Cursor agent transcripts: $cursorHome"
        $script:FoundRoots.Add(@{ tool = 'cursor'; label = 'Cursor (agent)'; path = $cursorHome })
        $dest = Join-Path $OutBase 'cursor-agent'
        $n = Collect-Tree -SourceRoot $cursorHome -DestRoot $dest `
            -Include @('*.jsonl', '*.json', '*.db', '*.db-wal', '*.db-shm',
                       '*.vscdb', '*.vscdb-wal', '*.vscdb-shm') `
            -Tool 'cursor'
        Write-Info "  $n file(s) matched (agent)"
    } else {
        Write-Miss 'Cursor agent transcripts (~/.cursor/projects/) - not found'
    }

    # IDE conversation DB: %APPDATA%\Cursor\User\
    $cursorUser = Join-Path $Env.APPDATA 'Cursor\User'
    if (Test-Path $cursorUser) {
        Write-Found "Cursor IDE data: $cursorUser"
        $script:FoundRoots.Add(@{ tool = 'cursor'; label = 'Cursor IDE'; path = $cursorUser })
        $dest = Join-Path $OutBase 'cursor-ide'
        $n = Collect-Tree -SourceRoot $cursorUser -DestRoot $dest `
            -Include @('conversation-search.db', 'conversation-search.db-wal',
                       'conversation-search.db-shm', '*.vscdb', '*.vscdb-wal',
                       '*.vscdb-shm', '*.json', '*.jsonl') `
            -Tool 'cursor'
        Write-Info "  $n file(s) matched (IDE)"
    } else {
        Write-Miss 'Cursor IDE data (%APPDATA%\Cursor\User\) - not found'
    }
}

function Collect-ChatGPT([hashtable]$Env, [string]$OutBase) {
    $found = $false

    # Standalone (roaming): %APPDATA%\OpenAI\ChatGPT\
    $roaming = Join-Path $Env.APPDATA 'OpenAI\ChatGPT'
    if (Test-Path $roaming) {
        Write-Found "ChatGPT Desktop (standalone): $roaming"
        $script:FoundRoots.Add(@{ tool = 'chatgpt'; label = 'ChatGPT Desktop'; path = $roaming })
        $dest = Join-Path $OutBase 'chatgpt'
        $n = Collect-Tree -SourceRoot $roaming -DestRoot $dest `
            -Include @('*.db', '*.sqlite', '*.sqlite-wal', '*.sqlite-shm',
                       'CURRENT', 'MANIFEST-*', '*.ldb', '*.sst', '*.log', '*.json') `
            -Tool 'chatgpt'
        Write-Info "  $n file(s) matched (standalone)"
        $found = $true
    }

    # Local: %LOCALAPPDATA%\OpenAI\ChatGPT\
    $local = Join-Path $Env.LOCALAPPDATA 'OpenAI\ChatGPT'
    if (Test-Path $local) {
        Write-Found "ChatGPT Desktop (local): $local"
        $script:FoundRoots.Add(@{ tool = 'chatgpt'; label = 'ChatGPT Desktop (local)'; path = $local })
        $dest = Join-Path $OutBase 'chatgpt-local'
        $n = Collect-Tree -SourceRoot $local -DestRoot $dest `
            -Include @('*.db', '*.sqlite', '*.sqlite-wal', '*.sqlite-shm',
                       'CURRENT', 'MANIFEST-*', '*.ldb', '*.sst', '*.log', '*.json') `
            -Tool 'chatgpt'
        Write-Info "  $n file(s) matched (local)"
        $found = $true
    }

    # MS Store: %LOCALAPPDATA%\Packages\OpenAI.ChatGPT-*\LocalCache\Roaming\ChatGPT\
    $pkgBase = Join-Path $Env.LOCALAPPDATA 'Packages'
    if (Test-Path $pkgBase -PathType Container) {
        $pkgDirs = Get-ChildItem $pkgBase -Directory -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -imatch '^openai\.chatgpt' }
        foreach ($pkg in $pkgDirs) {
            $chatgptPkg = Join-Path $pkg.FullName 'LocalCache\Roaming\ChatGPT'
            if (Test-Path $chatgptPkg) {
                Write-Found "ChatGPT Desktop (MS Store): $chatgptPkg"
                $script:FoundRoots.Add(@{ tool = 'chatgpt'; label = 'ChatGPT (MS Store)'; path = $chatgptPkg })
                $pkgSafe = $pkg.Name -replace '[^a-zA-Z0-9]', '-'
                $dest    = Join-Path $OutBase "chatgpt-msstore-$pkgSafe"
                $n = Collect-Tree -SourceRoot $chatgptPkg -DestRoot $dest `
                    -Include @('*.db', '*.sqlite', '*.sqlite-wal', '*.sqlite-shm',
                               'CURRENT', 'MANIFEST-*', '*.ldb', '*.sst', '*.log', '*.json') `
                    -Tool 'chatgpt'
                Write-Info "  $n file(s) matched (MS Store)"
                $found = $true
            }
        }
    }

    if (-not $found) { Write-Miss 'ChatGPT Desktop - not found' }
}

function Collect-CopilotVSCode([hashtable]$Env, [string]$OutBase) {
    $products = @('Code', 'Code - Insiders', 'VSCodium', 'VSCodium - Insiders')
    $anyFound = $false
    foreach ($prod in $products) {
        $wsRoot      = Join-Path $Env.APPDATA "$prod\User\workspaceStorage"
        $globalEmpty = Join-Path $Env.APPDATA "$prod\User\globalStorage\emptyWindowChatSessions"
        if (-not (Test-Path $wsRoot) -and -not (Test-Path $globalEmpty)) { continue }

        # Validate: has chatSessions or emptyWindowChatSessions
        $hasChatSessions = $false
        if (Test-Path $globalEmpty) {
            $hasChatSessions = $true
        } elseif (Test-Path $wsRoot) {
            $firstWs = Get-ChildItem $wsRoot -Directory -ErrorAction SilentlyContinue |
                       Where-Object { Test-Path (Join-Path $_.FullName 'chatSessions') } |
                       Select-Object -First 1
            if ($firstWs) { $hasChatSessions = $true }
        }
        if (-not $hasChatSessions) { continue }

        Write-Found "GitHub Copilot ($prod): $wsRoot"
        $script:FoundRoots.Add(@{ tool = 'copilot'; label = "Copilot ($prod)"; path = $wsRoot })
        $safeName = $prod -replace ' ', '-' -replace '[^a-zA-Z0-9-]', ''
        $destWs   = Join-Path $OutBase "copilot-$safeName-workspaceStorage"
        $n = Collect-Tree -SourceRoot $wsRoot -DestRoot $destWs `
            -Include @('*.json', '*.jsonl', '*.db', '*.db-wal', '*.db-shm') `
            -Tool 'copilot'
        Write-Info "  $n file(s) matched (workspaceStorage)"
        if (Test-Path $globalEmpty) {
            $destGe = Join-Path $OutBase "copilot-$safeName-emptyWindow"
            $m = Collect-Tree -SourceRoot $globalEmpty -DestRoot $destGe `
                -Include @('*.json', '*.jsonl') -Tool 'copilot'
            Write-Info "  $m file(s) matched (emptyWindowChatSessions)"
        }
        $anyFound = $true
    }
    if (-not $anyFound) { Write-Miss 'GitHub Copilot (VS Code) - no chatSessions found' }
}

function Collect-CopilotCli([hashtable]$Env, [string]$OutBase) {
    $copilotHome = if ($env:COPILOT_HOME) { $env:COPILOT_HOME }
                   else                   { Join-Path $Env.USERPROFILE '.copilot' }
    $hasSessions = Test-Path (Join-Path $copilotHome 'session-state')
    $hasDb       = Test-Path (Join-Path $copilotHome 'session-store.db')
    if (-not $hasSessions -and -not $hasDb) {
        Write-Miss 'GitHub Copilot CLI (~/.copilot/) - not found'; return
    }
    Write-Found "GitHub Copilot CLI: $copilotHome"
    $script:FoundRoots.Add(@{ tool = 'copilot'; label = 'Copilot CLI'; path = $copilotHome })
    $dest = Join-Path $OutBase 'copilot-cli'
    $n = Collect-Tree -SourceRoot $copilotHome -DestRoot $dest `
        -Include @('*.jsonl', '*.json', '*.yaml', '*.yml', '*.md',
                   '*.db', '*.db-wal', '*.db-shm') `
        -Exclude @('config.json', 'tokens.json', 'oauth*.json') `
        -Tool 'copilot'
    Write-Info "  $n file(s) matched"
}

function Collect-Windsurf([hashtable]$Env, [string]$OutBase) {
    $wsUser = Join-Path $Env.APPDATA 'Windsurf\User'
    if (-not (Test-Path $wsUser)) {
        Write-Miss 'Windsurf (%APPDATA%\Windsurf\User\) - not found'; return
    }
    Write-Found "Windsurf: $wsUser"
    $script:FoundRoots.Add(@{ tool = 'windsurf'; label = 'Windsurf'; path = $wsUser })
    $dest = Join-Path $OutBase 'windsurf'
    $n = Collect-Tree -SourceRoot $wsUser -DestRoot $dest `
        -Include @('*.vscdb', '*.vscdb-wal', '*.vscdb-shm',
                   '*.db', '*.db-wal', '*.db-shm', '*.json', '*.jsonl') `
        -Tool 'windsurf'
    Write-Info "  $n file(s) matched"
}

function Collect-Continue([hashtable]$Env, [string]$OutBase) {
    $continueHome = if ($env:CONTINUE_GLOBAL_DIR) { $env:CONTINUE_GLOBAL_DIR }
                    else                           { Join-Path $Env.USERPROFILE '.continue' }
    if (-not (Test-Path (Join-Path $continueHome 'sessions'))) {
        Write-Miss 'Continue.dev (~/.continue/) - not found'; return
    }
    Write-Found "Continue.dev: $continueHome"
    $script:FoundRoots.Add(@{ tool = 'continue'; label = 'Continue.dev'; path = $continueHome })
    $dest = Join-Path $OutBase 'continue'
    $n = Collect-Tree -SourceRoot $continueHome -DestRoot $dest `
        -Include @('*.json', '*.jsonl', '*.yaml', '*.yml') `
        -Tool 'continue'
    Write-Info "  $n file(s) matched"
}

# -- Manifest + summary -------------------------------------------------------
function Write-Manifest([string]$OutDir, [string]$ProfileLabel, [string]$ComputerName) {
    $elapsed = (Get-Date) - $script:StartTime
    $summary = @{
        collectedAt      = $script:StartTime.ToString('o')
        collectionHost   = $ComputerName
        profileLabel     = $ProfileLabel
        elapsedSeconds   = [Math]::Round($elapsed.TotalSeconds, 1)
        filesCollected   = $script:Collected
        filesSkippedSize = $script:SkippedSize
        errors           = $script:Errors
        maxFileSizeMB    = $MaxFileSizeMB
        sourcesFound     = $script:FoundRoots.Count
        sources          = @($script:FoundRoots)
        files            = @($script:ManifestRows)
    }
    $jsonPath = Join-Path $OutDir 'irflow-manifest.json'
    $summary | ConvertTo-Json -Depth 8 | Set-Content $jsonPath -Encoding UTF8

    $txtPath = Join-Path $OutDir 'irflow-manifest.txt'
    $lines   = @(
        "IRFlow Timeline - AI Artifact Collection Report",
        "================================================",
        "Collected : $($summary.collectedAt)",
        "Host      : $($summary.collectionHost)",
        "Profile   : $($summary.profileLabel)",
        "Elapsed   : $($summary.elapsedSeconds)s",
        "",
        "  Files collected  : $($script:Collected)",
        "  Files skipped    : $($script:SkippedSize) (exceeded $MaxFileSizeMB MB limit)",
        "  Copy errors      : $($script:Errors)",
        "",
        "Artifact sources found ($($script:FoundRoots.Count)):"
    )
    foreach ($r in $script:FoundRoots) {
        $lines += "  [$($r.tool.PadRight(16))]  $($r.label)"
        $lines += "                          $($r.path)"
    }
    if ($script:FoundRoots.Count -eq 0) {
        $lines += "  (none - no AI artifacts detected at standard paths)"
    }
    $lines += ""
    $lines += "Load into IRFlow Timeline:"
    $lines += "  Tools > Collect AI Artifacts > 'Browse folder' > select this folder."
    $lines | Set-Content $txtPath -Encoding UTF8
    return $txtPath
}

# -- Main ---------------------------------------------------------------------
Write-Banner

if (-not $OutputPath) {
    $ts         = Get-Date -Format 'yyyyMMdd-HHmmss'
    $OutputPath = Join-Path ([Environment]::GetFolderPath('Desktop')) "AI-Artifacts-$ts"
}
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)

if ($InventoryOnly) {
    Write-Host "  Mode: INVENTORY ONLY (no files will be copied)`n" -ForegroundColor Yellow
} else {
    if ($PSCmdlet.ShouldProcess($OutputPath, 'Create output folder')) {
        New-Item $OutputPath -ItemType Directory -Force | Out-Null
    }
    Write-Info "Output folder: $OutputPath"
}

$profilesToScan = @(Resolve-Profiles)

foreach ($profileRoot in $profilesToScan) {
    $userName = Split-Path $profileRoot -Leaf
    $envMap   = Get-ProfileEnv $profileRoot
    $outBase  = if ($profilesToScan.Count -gt 1) { Join-Path $OutputPath $userName } else { $OutputPath }

    Write-Section "Profile: $userName  ($profileRoot)"

    Collect-ClaudeCode    $envMap $outBase
    Collect-Codex         $envMap $outBase
    Collect-GrokBuild     $envMap $outBase
    Collect-GeminiCli     $envMap $outBase
    Collect-Cursor        $envMap $outBase
    Collect-ChatGPT       $envMap $outBase
    Collect-CopilotVSCode $envMap $outBase
    Collect-CopilotCli    $envMap $outBase
    Collect-Windsurf      $envMap $outBase
    Collect-Continue      $envMap $outBase
}

# -- Final report -------------------------------------------------------------
Write-Section 'Collection complete'
$elapsed = (Get-Date) - $script:StartTime

if (-not $InventoryOnly) {
    $txtPath = Write-Manifest -OutDir $OutputPath `
        -ProfileLabel ($profilesToScan -join '; ') `
        -ComputerName $env:COMPUTERNAME

    Write-Found "Files collected : $($script:Collected)"
    if ($script:SkippedSize -gt 0) { Write-Warn "Files skipped   : $($script:SkippedSize) (size limit)" }
    if ($script:Errors -gt 0)      { Write-Warn "Copy errors     : $($script:Errors)" }
    Write-Info  "Elapsed         : $([Math]::Round($elapsed.TotalSeconds,1))s"
    Write-Info  "Manifest        : $txtPath"
    Write-Host ""
    Write-Host "  Output folder: $OutputPath" -ForegroundColor Cyan

    if ($Compress -and $script:Collected -gt 0) {
        $zipPath = "$OutputPath.zip"
        Write-Info "Compressing to $zipPath ..."
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::CreateFromDirectory($OutputPath, $zipPath)
            $zipMB = [Math]::Round((Get-Item $zipPath).Length / 1MB, 1)
            Write-Found "Archive: $zipPath  ($zipMB MB)"
        } catch {
            Write-Warn "Compression failed: $($_.Exception.Message)"
        }
    }

    Write-Host ""
    Write-Host "  To analyse: IRFlow Timeline > Tools > Collect AI Artifacts > 'Browse folder'" -ForegroundColor Green
    Write-Host "              then select: $OutputPath" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "  Sources found ($($script:FoundRoots.Count)):" -ForegroundColor Cyan
    foreach ($r in $script:FoundRoots) {
        Write-Found "$($r.label.PadRight(28)) $($r.path)"
    }
    if ($script:FoundRoots.Count -eq 0) {
        Write-Miss 'No AI artifacts detected at standard Windows paths.'
    }
    Write-Host ""
    Write-Info "Elapsed: $([Math]::Round($elapsed.TotalSeconds,1))s"
}
Write-Host ""
