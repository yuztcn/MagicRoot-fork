# 系统应用 Root 检测清单

扫描范围：316 个系统包，命中 31 条 dex 记录，去重 28 个包。

## 检测方式分类

### /system/bin/su 文件检查

- com.baidu.swan
- com.google.android.gms
- com.hihonor.notepad
- com.hihonor.soundrecorder
- com.hihonor.videoeditor
- com.sohu.inputmethod.sogou.honor

### Honor HwSecurityDiagnoseManager / STP

- com.android.permissioncontroller
- com.android.settings
- com.hihonor.coauthservice
- com.hihonor.hiview
- com.hihonor.koBackup
- com.hihonor.nearby
- com.hihonor.parallelspace
- com.hihonor.remotepassword

### Magisk/路径检查

- com.hihonor.devicefinder
- com.hihonor.findmydevice

### 通用 isRooted/checkRoot

- com.android.packageinstaller
- com.hihonor.android.projectmenu
- com.hihonor.dms
- com.hihonor.eyesense
- com.hihonor.iaware
- com.hihonor.linktime
- com.hihonor.magicavatar
- com.hihonor.ouc
- com.hihonor.securitypluginbase
- com.hihonor.systemserver
- com.newcall
- com.os.callservice

## 逐包命中

| 包名 | 检测关键词 | APK |
|---|---|---|
| com.android.packageinstaller | isRooted | /system/priv-app/PackageInstaller/PackageInstaller.apk |
| com.android.permissioncontroller | @Lcom/hihonor/android/securitydiagnose/HwSecurityDiagnoseManager, SLcom/hihonor/android/securitydiagnose/HwSecurityDiagnoseManager$AntiMalProtectType, [Lcom/hihonor/android/securitydiagnose/HwSecurityDiagnoseManager$AntiMalProtectLauncherType | /apex/com.android.permission/priv-app/PermissionController@CP2A.260605.016/PermissionController.apk |
| com.android.settings | @Lcom/hihonor/android/securitydiagnose/HwSecurityDiagnoseManager, SLcom/hihonor/android/securitydiagnose/HwSecurityDiagnoseManager$AntiMalDataSrcType, SLcom/hihonor/android/securitydiagnose/HwSecurityDiagnoseManager$AntiMalProtectType, [Lcom/hihonor/android/securitydiagnose/HwSecurityDiagnoseManager$AntiMalProtectLauncherType | /system/priv-app/Settings/Settings.apk |
| com.baidu.swan | /system/bin/su | /system/app/Swan/Swan.apk |
| com.google.android.gms | /system/bin/su | /apex/com.google.android.gmssystem/priv-app/PrebuiltGmsCoreVic@361800000/PrebuiltGmsCoreVic.apk |
| com.hihonor.android.projectmenu | isRooted | /system/app/HnProjectMenu/HnProjectMenu.apk |
| com.hihonor.coauthservice | @Lcom/hihonor/android/securitydiagnose/HwSecurityDiagnoseManager, getRootStatusSync, msc.parallelspace.debug_mode | /system/app/HnCoAuthService/HnCoAuthService.apk |
| com.hihonor.devicefinder | isRooted, magisk | /system/app/DeviceFinder/DeviceFinder.apk |
| com.hihonor.dms | isRooted | /system/priv-app/dms/dms.apk |
| com.hihonor.eyesense | isRooted | /product_h/app/HnEyesense/HnEyesense.apk |
| com.hihonor.findmydevice | isRooted, magisk | /system/app/FindMyDevice/FindMyDevice.apk |
| com.hihonor.hiview | @Lcom/hihonor/android/securitydiagnose/HwSecurityDiagnoseManager, getRootStatusSync | /system/app/HiView/HiView.apk |
| com.hihonor.iaware | isRooted | /system/app/HnIAware/HnIAware.apk |
| com.hihonor.koBackup | /system/bin/su, 4Landroid/securitydiagnose/HwSecurityDiagnoseManager, @Lcom/hihonor/android/securitydiagnose/HwSecurityDiagnoseManager | /system/delapp/HnBackup/HnBackup.apk |
| com.hihonor.linktime | isRooted | /system/priv-app/HnLinkTime/HnLinkTime.apk |
| com.hihonor.magicavatar | isRooted | /product_h/region_comm/china/app/MagicAvatar/MagicAvatar.apk |
| com.hihonor.nearby | @Lcom/hihonor/android/securitydiagnose/HwSecurityDiagnoseManager, SLcom/hihonor/android/securitydiagnose/HwSecurityDiagnoseManager$StpExtraStatusInfo | /system/app/HnNearby/HnNearby.apk |
| com.hihonor.notepad | /system/bin/su | /system/priv-app/HnNotePad/HnNotePad.apk |
| com.hihonor.ouc |  isRootedByUser is ,  isRootedByUserForPay return true,  others:root, empty:not root) status = , (isRootedByUserForPay payCenter not exist, 6isRootedByUserForPay the payCenter Switch is not open., 8isRootedByUserForPay can not rooted by user by payCenter, GisRootedByUserForPay(0:not root, isRooted is , isRootedByUser rootStatus is  | /system/app/HnOUC/HnOUC.apk |
| com.hihonor.parallelspace | @Lcom/hihonor/android/securitydiagnose/HwSecurityDiagnoseManager, getRootStatusSync, msc.parallelspace.debug_mode | /product_h/region_comm/china/app/HnParallelSpace/HnParallelSpace.apk |
| com.hihonor.remotepassword | @Lcom/hihonor/android/securitydiagnose/HwSecurityDiagnoseManager, getRootStatusSync | /system/app/HnRemotePassword/HnRemotePassword.apk |
| com.hihonor.securitypluginbase | isRooted | /system/app/HnSecurityPluginBase/HnSecurityPluginBase.apk |
| com.hihonor.soundrecorder | /system/bin/su | /system/app/SoundRecorder/SoundRecorder.apk |
| com.hihonor.systemserver | 0checkRootState, permission ANTITHEFT not allowed, checkRootState, checkRootState, @removed, isRooted | /system/priv-app/HnSystemServer/HnSystemServer.apk |
| com.hihonor.videoeditor | /system/bin/su | /system/priv-app/HnVideoEditor/HnVideoEditor.apk |
| com.newcall | isRooted | /product_h/region_comm/china/app/NewCallSdk/NewCallSdk.apk |
| com.os.callservice | isRooted | /system/priv-app/VoipCallService/VoipCallService.apk |
| com.sohu.inputmethod.sogou.honor | 	checkRoot, 	isRooted=, /system/bin/su, isRooted | /product_h/region_comm/china/app/SogouInput_for_Honor/SogouInput_for_Honor.apk |

## 纯 KernelSU/SuSFS 覆盖说明

- HwSecurityDiagnoseManager / getRootStatusSync 类应用：清理 STP 后重启，root 状态由 STP 返回 0。

- /system/bin/su、magisk 类应用：由 SuSFS open_redirect 和 su entry 隐藏路径；这属于路径级隐藏，不做进程内 Hook。

- 通用 isRooted/checkRoot：多数仍走上述路径/属性检查；未做逐个应用 Hook，因此不能保证每应用都返回未 root。

- 本清单不依赖 RootHider/LSPosed/Xposed。

