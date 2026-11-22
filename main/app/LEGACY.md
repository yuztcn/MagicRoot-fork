# main/app 目录说明

当前真正参与构建的只有三项，其余为历史基线：

```text
assets/   compose 构建通过 sourceSets 打包进 APK（活跃）
res/      compose 构建通过 sourceSets 打包（活跃）
libs/     shizuku-*.jar，被 compose-app build.gradle.kts 引用（活跃）
```

以下为 1.0.x 早期手工打包流程的残留，**不参与当前构建，不要修改**：

```text
src/                旧版单文件控制器（1008 行），实际控制器是
                    main/compose-app/app/src/main/java/.../MainActivity.java
build-legacy.ps1    旧打包流程
pack_apk.py         旧打包流程
legacy-libs/        kotlin-stdlib.jar（现构建由 Kotlin 插件提供）
AndroidManifest.xml 旧清单（漂移，生效的是 compose-app/app/src/main/AndroidManifest.xml）
README.md           1.0.3 时代说明（BakaSU/双内核，已过时）
build.ps1           当前仍活跃：gradle 打包 + strip_baseline + zipalign + apksigner
```

保留原因：CLAUDE.md 要求把 `main/app/src/` 等作为 1.0.5 发布基线存档。
若将来确定不再需要，可整体移入 `legacy/` 顶层目录。
