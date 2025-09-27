# Configure IP addresses first
& "$PSScriptRoot\configure-ip.ps1"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to configure IP addresses"
    exit $LASTEXITCODE
}

# Run the specific IPv4 tests
Write-Host "Running IPv4 tests..."
cargo test ipv4 -- --ignored --no-capture --test-threads=1

# Store the exit code from cargo test
$testExitCode = $LASTEXITCODE

# Exit with the test result code
exit $testExitCode
