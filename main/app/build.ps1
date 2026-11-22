param(
    [Parameter(Mandatory = $true)][string]$Sdk,
    [Parameter(Mandatory = $true)][string]$Jdk,
    [Parameter(Mandatory = $true)][string]$Keystore,
    [Parameter(Mandatory = $true)][string]$StorePass,
    [string]$KeyAlias = "magicroot",
    [Parameter(Mandatory = $true)][string]$KeyPass
)
$ErrorActionPreference = "Stop"
$appRoot = $PSScriptRoot
$root = Split-Path -Parent $appRoot
$compose = Join-Path $root "compose-app"
$gradlew = Join-Path $compose "gradlew.bat"

if (-not (Test-Path $gradlew)) { throw "compose-app gradlew not found: $gradlew" }
if (-not (Test-Path (Join-Path $Jdk "bin\java.exe"))) { throw "JDK not found: $Jdk" }
if (-not (Test-Path (Join-Path $Sdk "platforms\android-37.0\android.jar"))) { throw "SDK Platform 37 not found: $Sdk" }

$env:JAVA_HOME = $Jdk
$env:ANDROID_HOME = $Sdk
$env:ANDROID_SDK_ROOT = $Sdk
# Keep Gradle's home inside the build tree: the file sandbox is
# workspace-write, so writing to %USERPROFILE%\.gradle is denied.  Set
# $env:GRADLE_USER_HOME beforehand to override (e.g. to reuse a warm cache).
if (-not $env:GRADLE_USER_HOME) {
    $env:GRADLE_USER_HOME = Join-Path $root ".gradle-home"
}
New-Item -ItemType Directory -Force -Path $env:GRADLE_USER_HOME | Out-Null
$env:MAGICROOT_KEYSTORE = (Resolve-Path $Keystore).Path
$env:MAGICROOT_STORE_PASS = $StorePass
$env:MAGICROOT_KEY_ALIAS = $KeyAlias
$env:MAGICROOT_KEY_PASS = $KeyPass

# Gradle needs a local.properties for non-standard SDK locations.
$localProperties = Join-Path $compose "local.properties"
$sdkEscaped = $Sdk.Replace('\', '\\').Replace(':', '\:')
Set-Content -Path $localProperties -Value "sdk.dir=$sdkEscaped" -Encoding ASCII

Push-Location $compose
try {
    & $gradlew --no-daemon --build-cache --no-watch-fs assembleRelease
    if ($LASTEXITCODE -ne 0) { throw "Gradle assembleRelease failed" }
} finally {
    Pop-Location
}

$built = Join-Path $compose "app\build\outputs\apk\release\app-release.apk"
if (-not (Test-Path $built)) { throw "APK not found: $built" }

# Remove the optional baseline profile assets (random binary bytes can trip
# desensitization scans) and re-sign the APK with the release key.
$strip = Join-Path $appRoot "..\..\tools\strip_baseline.py"
$stripped = Join-Path $appRoot "MagicRoot-stripped.apk"
$aligned = Join-Path $appRoot "MagicRoot-aligned.apk"
& python $strip $built $stripped
if ($LASTEXITCODE -ne 0) { throw "baseline strip failed" }
$buildToolsRoot = Join-Path $Sdk "build-tools"
$preferredBuildTools = Join-Path $buildToolsRoot "37.0.0"
if (Test-Path $preferredBuildTools) {
    $buildToolsDir = $preferredBuildTools
} else {
    $latestBuildTools = Get-ChildItem -Path $buildToolsRoot -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $latestBuildTools) { throw "No build-tools directory found under: $buildToolsRoot" }
    $buildToolsDir = $latestBuildTools.FullName
}
$zipalign = Join-Path $buildToolsDir "zipalign.exe"
$apksigner = Join-Path $buildToolsDir "apksigner.bat"
if (-not (Test-Path $zipalign)) { throw "zipalign not found: $zipalign" }
if (-not (Test-Path $apksigner)) { throw "apksigner not found: $apksigner" }
& $zipalign -f -p 4 $stripped $aligned
if ($LASTEXITCODE -ne 0) { throw "zipalign failed" }
$apksignerJar = Join-Path $buildToolsDir "lib\apksigner.jar"
& (Join-Path $Jdk "bin\java.exe") "--enable-native-access=ALL-UNNAMED" -jar $apksignerJar sign --ks $Keystore --ks-pass "pass:$StorePass" --ks-key-alias $KeyAlias --key-pass "pass:$KeyPass" --out (Join-Path $appRoot "MagicRoot.apk") $aligned
if ($LASTEXITCODE -ne 0) { throw "apksigner failed" }
Remove-Item -LiteralPath $stripped, $aligned -Force -ErrorAction SilentlyContinue
Write-Host "APK: $(Join-Path $appRoot 'MagicRoot.apk')"

