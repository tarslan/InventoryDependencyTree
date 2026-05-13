# Run from: C:\Arslan\UNL\PhD\PythonRelated\InventoryDependencyTree

$ErrorActionPreference = "Stop"
Set-Location "C:\Arslan\UNL\PhD\PythonRelated\InventoryDependencyTree"

$repoName = "InventoryDependencyTree"
$owner = "tarslan"
$remoteUrl = "https://github.com/$owner/$repoName.git"

# 1) Ensure git repo exists
if (-not (Test-Path ".git")) {
  git init
}
git branch -M main

# 2) Stage and commit current work
git add .
$pending = git diff --cached --name-only
if ($pending) {
  git commit -m "Initial commit: ML security pipeline (steps 0-6)"
} else {
  Write-Host "No staged changes to commit."
}

# 3) Create GitHub repo (requires gh CLI + login)
$ghExists = Get-Command gh -ErrorAction SilentlyContinue
if (-not $ghExists) {
  throw "GitHub CLI not found. Install from https://cli.github.com/ and run: gh auth login"
}

# Ensure authenticated
gh auth status | Out-Null

# Create repo if missing (public; change to --private if you want)
$repoCheck = gh repo view "$owner/$repoName" 2>$null
if (-not $repoCheck) {
  gh repo create "$owner/$repoName" --public --source . --remote origin
} else {
  Write-Host "Repo already exists on GitHub."
  $existingRemote = git remote get-url origin 2>$null
  if ($LASTEXITCODE -ne 0) {
    git remote add origin $remoteUrl
  } else {
    git remote set-url origin $remoteUrl
  }
}

# 4) Push
git push -u origin main

# 5) Verify
git remote -v
git status
Write-Host "Done. Repo URL: $remoteUrl"

