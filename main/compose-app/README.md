# compose-app

Compose Multiplatform / Miuix UI for MagicRoot.

- Source: `app/src/main/kotlin/com/aoki/magicroot/`
- Java controller: `app/src/main/java/com/aoki/magicroot/MainActivity.java`
- Assets: `../../app/assets`
- Resources: `../../app/res`
- Shizuku/Stellar jars: `../../app/libs`
- Stellar provider jar: `../../app/libs/stellar-provider.jar`

## Build

From repository root:

```powershell
.\compose-app\gradlew.bat -p compose-app assembleRelease
```

The canonical wrapper is `app/build.ps1`, which also passes signing values from
environment variables and copies the APK to `app/MagicRoot.apk`.

## Versions

```text
Gradle 9.3.1
AGP 9.1.0
Kotlin 2.4.20 (AGP built-in Kotlin)
Compose Multiplatform 1.12.0
Miuix 0.9.4
```

Miuix 0.9.4 requires Compose 1.12 and AGP 9.1; this project intentionally stays
with Compose 1.12.0 / AGP 9.1.0 / Gradle 9.3.1.

## License

Miuix is Apache-2.0. The Stellar provider jar is derived from the existing
`app/libs/stellar-classes2.dex`; the rest of the app keeps the project license.
