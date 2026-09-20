# Run as Administrator. Installs Sentinel as a SYSTEM scheduled task that starts at boot.
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$py = (Get-Command python).Source
$log = "C:\ProgramData\Sentinel"; New-Item -ItemType Directory -Force $log | Out-Null
$action  = New-ScheduledTaskAction -Execute $py -Argument "-m sentinel --live --audit $log\audit.jsonl" -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings= New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit 0
Register-ScheduledTask -TaskName "GoodAI Sentinel" -Action $action -Trigger $trigger -Settings $settings -User "SYSTEM" -RunLevel Highest -Force
Start-ScheduledTask -TaskName "GoodAI Sentinel"
Write-Host "Sentinel installed and started. Audit log: $log\audit.jsonl"
