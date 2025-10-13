# This script configures the IP address of the Ethernet adapter within the Docker container.

# Get the environment variables
$ip1 = $env:IP_ADDRESS_1
$ip2 = $env:IP_ADDRESS_2
$ip3 = $env:IP_ADDRESS_3
$prefixLength = $env:PREFIX_LENGTH

# Get the Ethernet adapter
$adapter = "Loopback Pseudo-Interface 2"
# $adapter = Get-NetAdapter | Where {$_.Name -like "Eth*"} | select -first 1
echo $adapter

if ($adapter) {
    try {
        # Configure the IP addresses
        New-NetIPAddress -InterfaceAlias $adapter -IPAddress $ip1 -PrefixLength $prefixLength
        New-NetIPAddress -InterfaceAlias $adapter -IPAddress $ip2 -PrefixLength $prefixLength
        New-NetIPAddress -InterfaceAlias $adapter -IPAddress $ip3 -PrefixLength $prefixLength
        # New-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress $ip1 -PrefixLength $prefixLength
        # New-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress $ip2 -PrefixLength $prefixLength
        # New-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress $ip3 -PrefixLength $prefixLength
        echo "IP1: $ip1/$prefixLength"
        Write-Host "IP2: $ip2/$prefixLength"
        Write-Host "IP3: $ip3/$prefixLength"
    } catch {
        Write-Error "Failed to configure IP addresses: $_"
        exit 1
    }
} else {
    Write-Error "No Ethernet adapter found"
    exit 1
}
