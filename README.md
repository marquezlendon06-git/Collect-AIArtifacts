```
   ____      _ _           _              _    ___         _   _  __
  / ___|___ | | | ___  ___| |_           / \  |_ _|       / \ |_ _|/ _| __ _  ___| |_ ___
 | |   / _ \| | |/ _ \/ __| __|  _____  / _ \  | |      / _ \ | || |_ / _` |/ __| __/ __|
 | |__| (_) | | |  __/ (__| |_  |_____| / ___ \ | |  _ / ___ \| ||  _| (_| | (__| |_\__ \
  \____\___/|_|_|\___|\___|\__|        /_/   \_\___| (_)_/   \_\___|_|  \__,_|\___|\__|___/
```

> **Forensic triage script** — collect AI assistant conversation artifacts from a Windows user profile for analysis in [IRFlow Timeline](https://r3nzsec.github.io/irflow-timeline/).

---

## Overview

`Collect-AIArtifacts.ps1` is a standalone PowerShell script that discovers and copies conversation history, session files, and workspace databases left behind by popular AI coding assistants and chat tools.  
The collected folder mirrors the source directory structure so it can be loaded directly into **IRFlow Timeline** via *Tools → Collect AI Artifacts → Browse folder*.

---

## Supported Tools

| Tool | Artifact Location |
|---|---|
| **Claude Code CLI** | `~/.claude/` |
| **Claude Desktop** (Cowork / local-agent-mode) | `%APPDATA%\Claude\` |
| **OpenAI Codex CLI** | `~/.codex/` |
| **xAI Grok Build** | `~/.grok/` |
| **ChatGPT Desktop** (standalone, MS Store) | `%APPDATA%\OpenAI\ChatGPT\`, `%LOCALAPPDATA%\...` |
| **Gemini CLI** | `~/.gemini/` |
| **Cursor** (agent transcripts + IDE conversation DB) | `~/.cursor/`, `%APPDATA%\Cursor\User\` |
| **GitHub Copilot** (VS Code products + CLI) | `%APPDATA%\Code\User\workspaceStorage\`, `~/.copilot/` |
| **Windsurf** | `%APPDATA%\Windsurf\User\` |
| **Continue.dev** | `~/.continue/` |

---

## Requirements

- **Windows** (PowerShell 5.1 or later)
- No external modules required — pure built-in PowerShell

---

## Usage

### Basic — collect current user, output to Desktop

```powershell
.\Collect-AIArtifacts.ps1
```

### Collect and compress to a ZIP archive

```powershell
.\Collect-AIArtifacts.ps1 -OutputPath C:\IRCase\AI -Compress
```

### Collect from a mounted forensic image

```powershell
.\Collect-AIArtifacts.ps1 -ProfilePath D:\Image\Users\victim -OutputPath C:\IRCase\AI
```

### Scan every profile under C:\Users\

```powershell
.\Collect-AIArtifacts.ps1 -AllUsers -OutputPath C:\IRCase\AI
```

### Inventory only — discover without copying

```powershell
.\Collect-AIArtifacts.ps1 -InventoryOnly
```

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-OutputPath` | `string` | `Desktop\AI-Artifacts-<timestamp>` | Destination folder for collected artifacts |
| `-ProfilePath` | `string` | Current user's profile | Source profile root (useful for offline/mounted images) |
| `-AllUsers` | `switch` | — | Scan every profile under `C:\Users\` |
| `-Compress` | `switch` | — | ZIP the output folder after collection |
| `-InventoryOnly` | `switch` | — | Discover artifact roots without copying files |
| `-MaxFileSizeMB` | `int` | `200` | Skip individual files larger than this (listed as `skipped-size` in manifest) |

---

## Output

After collection the output folder contains:

```
AI-Artifacts-<timestamp>\
├── claude-code-cli\        # Claude Code CLI artifacts
├── claude-desktop\         # Claude Desktop session files
├── codex\                  # OpenAI Codex history
├── cursor-agent\           # Cursor agent transcripts
├── cursor-ide\             # Cursor IDE conversation databases
├── chatgpt\                # ChatGPT Desktop data
├── copilot-Code-...\       # GitHub Copilot workspace storage
├── windsurf\               # Windsurf AI data
├── continue\               # Continue.dev sessions
├── irflow-manifest.json    # Machine-readable collection manifest
└── irflow-manifest.txt     # Human-readable summary report
```

The `irflow-manifest.json` records every file collected, skipped, or errored with timestamps and sizes — ready for chain-of-custody documentation.

---

## IRFlow Timeline Integration

1. Open **IRFlow Timeline** → `Tools` → `Collect AI Artifacts`
2. Click **Browse folder** and select the output folder (or point it at the `.zip`)
3. All supported artifacts are parsed and visualised on the timeline

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

> Made for forensic investigators and security researchers.  
> Part of the [IRFlow Timeline](https://r3nzsec.github.io/irflow-timeline/) toolchain.
