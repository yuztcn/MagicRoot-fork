param(
    [Parameter(Mandatory = $true)][string]$Sdk,
    [Parameter(Mandatory = $true)][string]$Jdk,
    [Parameter(Mandatory = $true)][string]$Keystore,
    [Parameter(Mandatory = $true)][string]$StorePass,
    [string]$KeyAlias = "magicroot",
    [Parameter(Mandatory = $true)][string]$KeyPass
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$bt = Join-Path $Sdk "build-tools\37.0.0"
$androidJar = Join-Path $Sdk "platforms\android-37.0\android.jar"
$env:JAVA_HOME = $Jdk
$env:PATH = "$Jdk\bin;$bt;$env:PATH"

if (-not (Test-Path $Keystore)) { throw "keystore not found" }

$out = Join-Path $root "build"
Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path "$out\classes","$out\dex" | Out-Null

Write-Host "== aapt2 compile =="
$res = Join-Path $root "res"
$resZip = Join-Path $out "res.zip"
if (Test-Path $res) {
    & "$bt\aapt2.exe" compile --dir $res -o $resZip
    if ($LASTEXITCODE -ne 0) { throw "aapt2 compile failed" }
}

Write-Host "== aapt2 link =="
$link = @('link','-o',"$out\base.apk",'-I',$androidJar,'--manifest',"$root\AndroidManifest.xml",'--min-sdk-version','34','--target-sdk-version','37')
if (Test-Path $resZip) { $link += @('-R',$resZip) }
& "$bt\aapt2.exe" @link
if ($LASTEXITCODE -ne 0) { throw "aapt2 link failed" }

Write-Host "== javac =="
$cp = "$androidJar;$root\libs\*"
& "$Jdk\bin\javac.exe" -source 17 -target 17 -encoding UTF-8 -classpath $cp -d "$out\classes" "$root\src\com\aoki\magicroot\MainActivity.java"
if ($LASTEXITCODE -ne 0) { throw "javac failed" }

Write-Host "== jar + d8 =="
& "$Jdk\bin\jar.exe" cf "$out\app.jar" -C "$out\classes" .
& "$bt\d8.bat" --lib $androidJar --min-api 30 --output "$out\dex" "$out\app.jar" "$root\libs\shizuku-api.jar" "$root\libs\shizuku-aidl.jar" "$root\libs\shizuku-shared.jar" "$root\libs\shizuku-provider.jar" "$root\libs\stellar-provider.jar" "$root\legacy-libs\kotlin-stdlib.jar"
if ($LASTEXITCODE -ne 0) { throw "d8 failed" }

Write-Host "== add assets + dex =="
python "$root\pack_apk.py" "$root" "$out"
if ($LASTEXITCODE -ne 0) { throw "pack failed" }

Write-Host "== zipalign + sign =="
& "$bt\zipalign.exe" -f 4 "$out\unsigned.apk" "$out\aligned.apk"
$ks = (Resolve-Path $Keystore).Path
$apksignerJar = Join-Path $bt "lib\apksigner.jar"
& (Join-Path $Jdk "bin\java.exe") "--enable-native-access=ALL-UNNAMED" -jar $apksignerJar sign --ks $ks --ks-key-alias $KeyAlias --ks-pass "pass:$StorePass" --key-pass "pass:$KeyPass" --out "$root\MagicRoot.apk" "$out\aligned.apk"
if ($LASTEXITCODE -ne 0) { throw "apksigner failed" }
Write-Host "APK: $root\MagicRoot.apk"
