# Check for Administrator Privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script with Administrator privileges." -ForegroundColor Red
    pause
    exit
}

# Define variables
$ScriptPath = $MyInvocation.MyCommand.Path
$FibratusGitHubAPI = "https://api.github.com/repos/rabbitstack/fibratus/releases/latest"
$RulesRepoURL = "https://github.com/N0vaSky/Custom-Fibratus-Rules/archive/refs/heads/main.zip"
$RulesDownloadPath = "$env:TEMP\FibratusRules.zip"
$RulesExtractPath = "$env:TEMP\FibratusRules"
$RulesTargetPath = "C:\Program Files\Fibratus"
$ServiceName = "Fibratus"
$TaskName = "FibratusUpdater"
$AdminGroup = "Administrators"  # Security Group for Allowed Execution

# Enforce Security Group Check
$User = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object System.Security.Principal.WindowsPrincipal($User)
$AdminGroupSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")  # SID for Administrators

if (-not $Principal.IsInRole($AdminGroupSid)) {
    Write-Host "Access Denied: Only members of the '$AdminGroup' group can execute this script." -ForegroundColor Red
    pause
    exit
}

# Get latest Fibratus release version dynamically
Write-Host "Checking latest Fibratus release..."
$LatestRelease = Invoke-RestMethod -Uri $FibratusGitHubAPI
$LatestVersion = $LatestRelease.tag_name -replace 'v',''
$FibratusInstaller = "fibratus-$LatestVersion-amd64.msi"
$FibratusDownloadURL = "https://github.com/rabbitstack/fibratus/releases/download/v$LatestVersion/$FibratusInstaller"
$DownloadPath = "$env:TEMP\$FibratusInstaller"

Write-Host "Latest version found: $LatestVersion"

# Uninstall existing Fibratus
Write-Host "`nChecking for existing Fibratus installation..."
$FibratusUninstaller = Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE Name='Fibratus'" | Select-Object -ExpandProperty IdentifyingNumber
if ($FibratusUninstaller) {
    Write-Host "Uninstalling existing Fibratus..."
    Start-Process msiexec.exe -ArgumentList "/x $FibratusUninstaller /quiet /norestart" -Wait
} else {
    Write-Host "No existing Fibratus installation found."
}

# Remove Fibratus service if it exists
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "Stopping and removing existing Fibratus service..."
    Stop-Service -Name $ServiceName -Force
    sc.exe delete $ServiceName | Out-Null
}

# Remove existing Fibratus directory if it exists
if (Test-Path $RulesTargetPath) {
    Write-Host "Removing previous Fibratus directory..."
    Remove-Item -Path $RulesTargetPath -Recurse -Force
}

# Download and install latest Fibratus version
Write-Host "Downloading Fibratus ($LatestVersion)..."
Invoke-WebRequest -Uri $FibratusDownloadURL -OutFile $DownloadPath

Write-Host "Installing Fibratus silently..."
Start-Process msiexec.exe -ArgumentList "/i `"$DownloadPath`" /quiet /norestart" -Wait

# Ensure Fibratus directory exists after installation
if (-not (Test-Path $RulesTargetPath)) {
    Write-Host "Fibratus installation failed or directory not found!" -ForegroundColor Red
    exit
}

# Download and apply Fibratus rules
Write-Host "Downloading custom Fibratus rules..."
Invoke-WebRequest -Uri $RulesRepoURL -OutFile $RulesDownloadPath

Write-Host "Extracting rules..."
Expand-Archive -Path $RulesDownloadPath -DestinationPath $RulesExtractPath -Force

Write-Host "Copying rules to Fibratus directory..."
$ExtractedRulesPath = Get-ChildItem "$RulesExtractPath\Custom-Fibratus-Rules-main" -Recurse -Filter "*.yml"
foreach ($rule in $ExtractedRulesPath) {
    if ($rule.Name -eq "macros.yml") {
        # Define destination for macros.yml in the macros folder and create the folder if needed
        $DestinationFolder = Join-Path -Path $RulesTargetPath -ChildPath "Rules\macros"
        if (-not (Test-Path $DestinationFolder)) {
            New-Item -Path $DestinationFolder -ItemType Directory -Force | Out-Null
        }
        $Destination = Join-Path -Path $DestinationFolder -ChildPath $rule.Name
    }
    else {
        $Destination = Join-Path -Path $RulesTargetPath -ChildPath "Rules\$($rule.Name)"
    }
    Copy-Item -Path $rule.FullName -Destination $Destination -Force
}

Write-Host "Custom Fibratus rules updated successfully."

# Restart Fibratus service
Write-Host "Restarting Fibratus service..."
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Restart-Service -Name $ServiceName -Force
    Write-Host "Fibratus service restarted successfully."
} else {
    Write-Host "Fibratus service not found. It may not be running yet."
}

# Remove specific rule file
$RuleToDelete = Join-Path -Path $RulesTargetPath -ChildPath "Rules\defense_evasion_unsigned_dll_injection_via_remote_thread.yml"
if (Test-Path $RuleToDelete) {
    Write-Host "Removing Unisgned DLL rule file..."
    Remove-Item -Path $RuleToDelete -Force
    Write-Host "Rule file removed successfully."
} else {
    Write-Host "Specified rule file not found."
}
$RuleToDelete2 = Join-Path -Path $RulesTargetPath -ChildPath "Rules\defense_evasion_potential_process_injection_via_tainted_memory_section.yml"
if (Test-Path $RuleToDelete2) {
    Write-Host "Removing Unisgned DLL rule file..."
    Remove-Item -Path $RuleToDelete -Force
    Write-Host "Rule file removed successfully."
} else {
    Write-Host "Specified rule file not found."
}
$RuleToDelete3 = Join-Path -Path $RulesTargetPath -ChildPath "Rules\credential_access_potential_sam_hive_dumping.yml"
if (Test-Path $RuleToDelete3) {
    Write-Host "Removing Unisgned DLL rule file..."
    Remove-Item -Path $RuleToDelete -Force
    Write-Host "Rule file removed successfully."
} else {
    Write-Host "Specified rule file not found."
}

# Cleanup temporary files
Remove-Item -Path $DownloadPath -Force
Remove-Item -Path $RulesDownloadPath -Force
Remove-Item -Path $RulesExtractPath -Recurse -Force

Write-Host "Installation, cleanup, rule update, and service restart completed successfully."

# Enforce Scheduled Task Security Group
Write-Host "`nChecking for existing scheduled task..."
$TaskExists = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

if ($TaskExists) {
    Write-Host "Scheduled task already exists. Updating it..."
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

Write-Host "Creating a new scheduled task to run as SYSTEM..."
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File `"$ScriptPath`" -NoProfile -ExecutionPolicy Bypass"
$Trigger = New-ScheduledTaskTrigger -Daily -At 2:00AM
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings

Write-Host "Scheduled task created successfully to run daily at 2:00 AM as SYSTEM." -ForegroundColor Green
