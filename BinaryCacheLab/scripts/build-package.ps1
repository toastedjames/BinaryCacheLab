param([string]$ProjectRoot=(Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference='Stop'
$classes=Join-Path $ProjectRoot ('build/classes-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $classes -Force | Out-Null
$sources=@(Get-ChildItem (Join-Path $ProjectRoot 'src/main/java') -Recurse -Filter '*.java' | ForEach-Object {$_.FullName})
& javac --release 17 -encoding UTF-8 -d $classes $sources
if($LASTEXITCODE -ne 0){throw 'Compilation failed'}
$jar=Join-Path $ProjectRoot 'binarycachelab.jar'
& jar --create --file $jar --main-class org.binarycachelab.BinaryCacheLabCli -C $classes .
if($LASTEXITCODE -ne 0){throw 'JAR creation failed'}
$hash=(Get-FileHash $jar -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $ProjectRoot 'binarycachelab.jar.sha256'),$hash+'  binarycachelab.jar'+[Environment]::NewLine)
Write-Output $jar
