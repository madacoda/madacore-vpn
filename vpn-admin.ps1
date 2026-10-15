<#
.SYNOPSIS
    MadaCore VPN Host CLI Wrapper for PowerShell (Windows / Hyper-V / Docker Desktop)
.EXAMPLE
    .\vpn-admin.ps1 list-users
    .\vpn-admin.ps1 create-user gamer1@gmail.com --devices pc,phone
#>
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CliArgs
)

$ContainerName = "gaming-wireguard"
$Running = docker ps --format '{{.Names}}' 2>$null | Select-String -Pattern "^$ContainerName$"

if ($Running) {
    docker exec -it $ContainerName python3 /app/manage_vpn.py @CliArgs
} else {
    python manage_vpn.py @CliArgs
}
