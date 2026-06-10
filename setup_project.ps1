param(
    [string]$PythonVersion = "3.12",
    [string]$VenvPath = ".venv",
    [switch]$SkipYaraCli
)

$ErrorActionPreference = "Stop"

function Resolve-Python {
    param([string]$Version)

    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        try {
            $candidate = (& py "-$Version" -c "import sys; print(sys.executable)") 2>$null
            if ($LASTEXITCODE -eq 0 -and $candidate) {
                return @("py", "-$Version")
            }
        } catch {}
    }

    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        return @("python")
    }

    throw "Python was not found. Install Python 3.10+ first."
}

function Install-YaraCli {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/VirusTotal/yara/releases/latest"
    $asset = $release.assets | Where-Object { $_.name -match "win64\.zip$" } | Select-Object -First 1
    if (-not $asset) {
        throw "No Windows 64-bit YARA CLI asset found in latest VirusTotal/yara release."
    }

    $cacheDir = Join-Path (Get-Location) ".setup_cache"
    $zipPath = Join-Path $cacheDir $asset.name
    $extractDir = Join-Path $cacheDir "yara-cli"
    $targetDir = Join-Path (Get-Location) "3rdparty\yara"

    New-Item -ItemType Directory -Force -Path $cacheDir, $targetDir | Out-Null
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath

    if (Test-Path $extractDir) {
        Remove-Item -Recurse -Force -LiteralPath $extractDir
    }
    Expand-Archive -LiteralPath $zipPath -DestinationPath $extractDir -Force

    $yara64 = Get-ChildItem -Path $extractDir -Recurse -Filter "yara64.exe" | Select-Object -First 1
    $yarac64 = Get-ChildItem -Path $extractDir -Recurse -Filter "yarac64.exe" | Select-Object -First 1
    if (-not $yara64 -or -not $yarac64) {
        throw "Downloaded YARA archive does not contain yara64.exe and yarac64.exe."
    }

    Copy-Item -LiteralPath $yara64.FullName -Destination (Join-Path $targetDir "yara64.exe") -Force
    Copy-Item -LiteralPath $yarac64.FullName -Destination (Join-Path $targetDir "yarac64.exe") -Force

    Write-Host "YARA CLI installed:" (& (Join-Path $targetDir "yara64.exe") --version)
}

$pythonCmd = Resolve-Python -Version $PythonVersion
Write-Host "Using Python command: $($pythonCmd -join ' ')"

if (-not (Test-Path $VenvPath)) {
    $pythonArgs = @()
    if ($pythonCmd.Length -gt 1) {
        $pythonArgs = $pythonCmd[1..($pythonCmd.Length - 1)]
    }
    & $pythonCmd[0] @pythonArgs -m venv $VenvPath
}

$venvPython = Join-Path (Get-Location) "$VenvPath\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    throw "Venv Python not found at $venvPython"
}

& $venvPython -m pip install --upgrade pip setuptools wheel
& $venvPython -m pip install -r requirements.txt

if (-not $SkipYaraCli) {
    Install-YaraCli
}

& $venvPython -c "import tkinter, yara, yara_x, flask, pandas, pefile; print('Python setup OK'); print('Tk', tkinter.TkVersion); print('yara-python', yara.__version__); print('yara-x OK')"

Write-Host ""
Write-Host "Setup complete."
Write-Host "Activate venv: .\$VenvPath\Scripts\Activate.ps1"
Write-Host "Run Tkinter app: .\$VenvPath\Scripts\python.exe main.py"
