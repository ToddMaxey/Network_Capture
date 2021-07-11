<#Header - Lex Thomas, Keith Ramphal Net Session Capture in Powershell. Modified by Todd Maxey and Muath Deeb#>
# Add - Full frame capture by removing -Truncationlength 512
# Add - Wait till ENTER is pressed to stop trace
# Add - ARP cache and Kerberos ticket purge
# Moved - cache and ticket purge to after starting network trace as not to miss the traffic
# Add Hit "ENTER" to start and stop trace
# Add Elevated permission check
# Removed tracing FOR loop
# Add code to remove any previous NetEventSessions
# Moved Start-NetEventSession -Name NetCap42 to after the user hits ENTER to start the trace. Previously the trace was starting before we flushed the caches
# Adding new line to flush ALL Kerberos tickets on the machine - Get-WmiObject Win32_LogonSession | Where-Object {$_.AuthenticationPackage -ne 'NTLM'} | ForEach-Object {klist.exe purge -li ([Convert]::ToString($_.LogonId, 16))} - Muath Deeb
# Moving the resolver cache and Kerberos flush to just after starting the network trace so we can pick up this traffic
# Added a Netstat -anob output file to corrlate the PID in the trace note to an executable 
#
Write-Host ""
Write-Host "Checking for elevated permissions..." -ForegroundColor Yellow
Write-Host ""
#[Security.Principal.WindowsBuiltInRole] "Administrator")) {
#Write-Host "Insufficient permissions to run this script. Open the PowerShell console as an administrator and run this script again." -ForegroundColor Red
#Write-Host ""
#Break
#}
#else {
#Write-Host ""
#Write-Host "Code is running as administrator - go on executing the script..." -ForegroundColor Green
#Write-Host ""
#}
# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))
{
 if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
  $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
  Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
  Exit
 }
}
#Where we write the captured data
$path = "C:\temp\capture\"
#Is the path does not exist, create it
If(!(test-path $path))
{
New-Item -ItemType Directory -Force -Path $path
}
#Remove any previous NetEventCapture sessions
Stop-NetEventSession -name NetCap42 -ErrorAction SilentlyContinue
Remove-NetEventSession -Name NetCap42 -ErrorAction SilentlyContinue

#this next line will gather computername as well as the time and format it with the following Computername Day-24hr Minute (This is at the START of the capture session)
Write-Host ""
Write-Host "Creating capture session" -ForegroundColor Yellow
New-NetEventSession -Name NetCap42 -LocalFilePath c:\temp\Capture\$env:computername" "$(get-date -f dddd-MMMM-dd-yyyy-HH.mm.ss).etl
Add-NetEventPacketCaptureProvider -SessionName NetCap42 -Truncationlength 65535

Write-Host ""
Write-Host "Press ENTER start capture session" -ForegroundColor Yellow
Read-Host " "

#Flush all resolver caches
Write-Host ""
Write-Host "Flushing DNS, NetBIOS, ARP and Kerberos caches" -ForegroundColor Yellow
ipconfig /Flushdns
Arp -d *
Nbtstat -RR

#flush kerberos tickets for user and machine
#Klist purge
#klist -li 0x3e7 purge  #machine
Get-WmiObject Win32_LogonSession | Where-Object {$_.AuthenticationPackage -ne 'NTLM'} | ForEach-Object {klist.exe purge -li ([Convert]::ToString($_.LogonId, 16))}

#Read-Host " "
Write-Host ""
Write-host "Please reproduce issue NOW." -ForegroundColor Green
Start-NetEventSession -Name NetCap42
Write-Host ""
Write-Host "Press ENTER to stop capture session when reproduction is complete" -ForegroundColor Yellow
Read-Host " "
netstat -anob > c:\temp\Capture\$env:computername" Netstat "$(get-date -f dddd-MMMM-dd-yyyy-HH.mm.ss).txt
Write-Host "Retrive your ETL trace file @ $path"  -ForegroundColor Yellow
Write-Host "Opening Explorer to $path"  -ForegroundColor Yellow
Stop-NetEventSession -name NetCap42
Remove-NetEventSession -name NetCap42 
Start-sleep -s 5

#Open file Explorer to capture location
explorer $path

Exit