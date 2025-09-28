Import-Module "$env:ChocolateyInstall/helpers/chocolateyInstaller.psm1"
refreshenv
$ips = @("192.168.0.6", "192.168.0.7", "192.168.0.8")
$devcon = (Get-Command devcon64.exe).Source
# Create three Microsoft KM-TEST Loopback Adapters
1..3 | ForEach-Object {
    & $devcon install "$env:WINDIR\Inf\netloop.inf" *msloop
}
Write-Host "waiting..."
Start-Sleep -Seconds 5
Write-Host "get adapters..."
# Grab the new adapters, rename them, and assign one IP each
$loopbacks = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*Loopback*" } | Sort-Object ifIndex
$loopbacks | Format-Table InterfaceAlias, InterfaceDescription, IPAddress, PrefixLength

if ($loopbacks.Count -lt 3) { throw "Expected 3 loopback adapters, found $($loopbacks.Count)" }
        
$aliases = @()
for ($i = 0; $i -lt 3; $i++) {
    $alias = "Loopback$($i+1)"
    $aliases += $alias
    Rename-NetAdapter -Name $loopbacks[$i].Name -NewName $alias
    # Assign /24 on each NIC (adjust as needed)
    New-NetIPAddress -InterfaceAlias $alias -IPAddress $ips[$i] -PrefixLength 24 | Out-Null
}

# Open firewall on those adapters regardless of profile/identifying state
# (InterfaceAlias scoping beats Public-profile blocks)
if (-not (Get-NetFirewallRule -DisplayName "Allow Loopbacks All In" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName "Allow Loopbacks All In" `
        -Direction Inbound -Action Allow -Protocol Any `
        -InterfaceAlias $aliases -Profile Any | Out-Null
}
Start-Sleep -Seconds 3

Write-Host "Configured:"
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -like "Loopback*" } | Format-Table InterfaceAlias, IPAddress, PrefixLength
    