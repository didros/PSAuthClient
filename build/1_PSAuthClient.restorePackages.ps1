param ( $basePath = "$PSScriptRoot\.." )
if ( !(Test-Path "$basePath\packages\nuget.exe") ) { 
    New-Item -ItemType Directory -Path "$basePath\packages" -Force | Out-Null
    Invoke-WebRequest 'https://dist.nuget.org/win-x86-commandline/latest/nuget.exe'-OutFile "$basePath\packages\nuget.exe" 
}
Write-Output "restore '$basePath\packages.config\' -verbosity detailed -configfile '$basePath\NuGet.config' -outputdirectory '$basePath\packages'"
# This does not work standard from PS, but works fin starting nuget.exe manually
Start-Process -FilePath "$basePath\packages\nuget.exe"  -Wait -NoNewWindow -ArgumentList "restore '$basePath\packages.config' -verbosity detailed -configfile '$basePath\NuGet.config' -outputdirectory '$basePath\packages'"