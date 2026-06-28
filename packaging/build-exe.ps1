# Build a portable single-file qer.exe with PyInstaller.
# Run from the repo root inside the project venv:
#   .\packaging\build-exe.ps1
# Output: dist\qer.exe  (no Python install required to run it)

param([string]$Python = ".\.venv\Scripts\python.exe")

& $Python -m pip install --quiet pyinstaller
& $Python -m PyInstaller --onefile --name qer --noconfirm --clean `
    --collect-submodules qer `
    packaging\qer_entry.py

if (Test-Path dist\qer.exe) {
    Write-Host "Built dist\qer.exe"
    & .\dist\qer.exe --version
} else {
    Write-Error "build failed"
}
