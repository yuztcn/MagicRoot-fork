# INTEGRATION-EVIDENCE 閳?MagicRoot 1.0.5-98260-dual (6.12.58 + 6.12.38)

> 閺堫剚鏋冩禒鑸垫Ц task-4 閻ㄥ嫭娓剁紒鍫ョ崣閺€鎯扮槈閹诡喓鈧倹澧嶉張澶嬫惙娴ｆ粌娼庨崷?workspace 閸愬懎鐣幋鎰剁窗
> **閺?adb閵嗕焦婀潻鐐村复閹靛婧€閵嗕焦婀€瑰顥?APK閵嗕焦婀幒銊┾偓浣碘偓浣规弓閸掗攱婧€**閵嗗倸甯慨?`MagicRoot-Enhanced-1.0.3/`
> 閺堫亣顫︽穱顔芥暭閿涘湯HA256SUMS 182/182 閺嶏繝鐛欓柅姘崇箖閿涘鈧?>
> 鐠囦焦宓侀弬鍥︽閿涘牊鐎鐑樻）韫?濞撳懎宕?badging/signer/閺嶏繝鐛欐潏鎾冲毉閿涘绱?> `work/integration-98260/build/`

---

## 1. 閻楀牊婀版稉搴濇唉娴犳ü楠囬悧?
| 妞?| 閸?|
|---|---|
| package | `com.aoki.magicroot` |
| **versionCode / versionName** | **10 / `1.0.5-98260-dual`**閿涘潏ompose `build.gradle.kts`閿涙泊egacy `main/app/AndroidManifest.xml` 閸氬本顒為敍?|
| **娑撹姘︽禒?APK** | `MagicRoot-Enhanced-1.0.4-98260/MagicRoot-1.0.5-98260-dual.apk` |
| **婢堆冪毈 / SHA256** | **4,076,170 B / `e4603d5e17b23737ba4fd42bb91ffe9069726ec20b1644d754bcffa1fdb98b56`** |
| 閺嬪嫬缂撶捄顖氱窞 | `main/app/build.ps1`閿涘湙radle 9.3.1 wrapper + AGP 9.1.0 + JDK 25 + SDK 37閿涘畭--no-daemon assembleRelease`閿?|
| badging | `package: name='com.aoki.magicroot' versionCode='10' versionName='1.0.5-98260-dual'`閿涘inSdk 34 / targetSdk 37 / compileSdk 37 |
| 缁涙儳鎮?| apksigner v2: `Verifies`閿涘牊婀伴張鐑樼ゴ鐠囨洝鐦夋稊?`CN=MagicRoot Build Verification (cert sha256 4bf96225閳?75adb)`閿涘SA 2048閿?*闂堢偛褰傜敮鍐劮閸?*閿?|
| legacy 閸忔粌绨?APK閿涘牓娼稉璁虫唉娴犳﹫绱?| `work/integration-98260/build/MagicRoot-legacy-1.0.5-98260-dual-vc10.apk`閿?,056,148 B閿涘HA256 `667a5acbf201fe02aa30c868b4f343ea017b1d3b5a634a037faee89d59d75062`閿涘潤egacy 閺嬪嫬缂撻棃鐐衡偓鎰摟閼哄倸褰叉径宥囧箛閿涘奔绮庨崗婊冪俺閿?|
| 娴犳挸绨遍弽鐟板綗婢舵牔绻氶悾?| `main/app/MagicRoot.apk`閿涘潌uild.ps1 閻ㄥ嫬鐖剁憴鍕翻閸戣桨缍呯純顕嗙礉娑撳孩鐗撮惄顔肩秿 APK 閸氬奔绔撮弬鍥︽閿?|

**閺嬪嫬缂撻崣顖氼槻閻滅増鈧?*閿涙艾鍠曠紒鎾圭翻閸忋儱鎮楁潻鐐电敾娑撱倖顐奸獮鎻掑櫍閺嬪嫬缂?
```text
BUILD SUCCESSFUL in 7s / Configuration cache entry reused
BUILD SUCCESSFUL in 8s / Configuration cache entry reused
BUILD_A SIZE=4076170 SHA256=E4603D5E閳ヮ毈DB98B56
BUILD_B SIZE=4076170 SHA256=E4603D5E閳ヮ毈DB98B56
REPRODUCIBLE=True
```

> **閺堚偓缂佸牓鍣稿楦款嚛閺勫函绱橪ead閿?026-10-26閿?*閿涙岸娉﹂幋?agent 娴溿倓绮惃?APK 娑擃叏绱漙assets/98260/SHA256SUMS.txt` 閸愬懐娈?`run98260.sh` 閸濆牆绗囬崑婊呮殌閸︺劏顕氶弬鍥︽閺堚偓缂佸牅鎱ㄧ拋顫閸?> 閿涘牊绔婚崡?`2277c502閳ヮ泦 vs 鐎圭偤妾?`1ada469d閳ヮ泦閿涘绱濈拋鎯ь槵娓?`check_assets` 娴兼俺顕ら幎?`FAIL=asset_hash`閵嗕竞ead 閻㈣鲸娓剁紒鍫熺爱閻焦鐖查柌宥嗘煀閻㈢喐鍨氬〒鍛礋
> 閿涘潉SHA256SUMS.txt` sha256 `9e825a2d閳ヮ泲46d4f`閿涘鑻熼悽銊ユ倱娑撯偓閸愯崵绮ㄩ弽鎴﹀櫢瀵?APK閿涙瓪8930034b516a598d93862e140b0d79c5e957b97388b3a4028fa1972a5d841cf5`閿?,973,556 B閿涘奔绨╁▎鈩冪€鍝勬惐鐢奔绔撮懛杈剧礆閿涘本婀伴弬鍥︽閹碘偓閺堝鏆熼崐闂翠簰鐠囥儲娓剁紒鍫熺€杞拌礋閸戝棎鈧?
## 2. 98260 鐠у嫪楠囬崫鍫濈瑖閺嶇顕敍鍫滅瑢 Lead 閻?port 閺嬪嫬缂撴稉鈧懛杈剧礆

`python tools/verify_98260_assets.py`閿涘牆鍙忛柈?OK閿涘绱?
```text
OK  exploit-android-perf         size=  66232 sha256=bd52314dcc5dc0fbdd2937c12b147050df5d910636422af904ec7381c9a516c5
OK  exploit-android-perf-chain   size=  66904 sha256=1cca57729824282c060d78235ff79b48506dadfc1d7ddeed15fadae2082e1047
OK  exploit-android-key-ptr      size=  80480 sha256=61bcb479e2a264ec3449e2fe32a5cfe8364f862e4797a09fecd03f66689a607b
OK  pc98260-su                   size=   8584 sha256=374bac50ff786af8e76486ee8f842d77a085bfa185b72d16af3d0755905db219

assets manifest vs port/98260-honor-61258/SHA256SUMS.txt: 4/4 OK
閿涘潷c98260-su 鐎电懓绨?port 閻?pc98260-su-client閿涘苯鐡ч懞鍌滄祲閸氬矉绱?```

APK 閸愬懘鈧劕鐡ч懞鍌涚壋鐎电櫢绱檂work/integration/apk_inventory.py`閿涘畱ompose 娑?legacy 閸氬嫪绔村▎鈽呯礆閿?
```text
# compose APK: assets 47 entries閿?8 娑?64560 鐠у嫪楠?+ 7 娑?98260 鐠у嫪楠?+ AGP dexopt 2 妞ょ櫢绱?98260/SHA256SUMS.txt             501   58a95ca3閳?27e4ea5
98260/exploit-android-key-ptr  80480   61bcb479閳ヮ泧607b      閳?娑?port 娑撯偓閼?98260/exploit-android-perf     66232   bd52314d閳ヮ泧516c5     閳?娑?port 娑撯偓閼?98260/exploit-android-perf-chain 66904 1cca5772閳ヮ泲1047      閳?娑?port 娑撯偓閼?98260/pc98260-su                8584   374bac50閳ヮ泭b219      閳?娑?port 娑撯偓閼?98260/run98260.sh              30047   82422d61閳?e9c669c
98260/target.sh                 2035   ee83eaad閳?7a1023f
source assets vs APK: identical=38 content_diff=0閿?4560 鐠у嫪楠囬梿璺哄綁閸栨牭绱?# legacy APK: assets 51 entries閿?8260/* + 98260-6138/* 閸忋劑鍎寸€涙ê婀稉鏂挎惐鐢奔绔撮懛?```

**Honor 6.12.38 閸欐ü缍嬮敍鍫熸拱濞嗏剝鏌婃晶鐑囩礉閻劍鍩涢幐鍥х暰 `Downloads/boot.img`閿?*

```text
target kernel: 6.12.38-android16-5-gfde7767f6ef6-abogki481467632-4k
kernel payload sha256: 48b622a20a700cdde0b8f2f6e83959df00a7efedf52f347377cf542f7b58948e
98260-6138/SHA256SUMS.txt            423   5c4b4385閳ヮ泴6a2f0b3
98260-6138/exploit-android-key-ptr 80480   d055e3fd閳?045ed7a
98260-6138/exploit-android-perf    66232   7a95e545閳?272f86c
98260-6138/exploit-android-perf-chain 66904 7ce538cb閳?3b5a69b
98260-6138/pc98260-su               8584   374bac50閳?905db219
98260-6138/target.sh                1890   80e5feda閳?45c2604
manifest vs port/98260-honor-61238/SHA256SUMS.txt: 4/4 OK
```

`tools/verify_apk.py`閿涘牆鍑℃穱顔碱槻閺?syms 閸濆牆绗囬獮鑸垫煀婢?98260 鐠у嫪楠?marker閿涘绱?
```text
- size: 3973556 B
- asset payload: 6713986 B (47 entries)
## Result
All required assets and flavor markers present.
```

## 3. 鐠佹儳顦笟褑鍓奸張?shell 鐠囶厽纭跺Λ鈧弻?
閺堫剚婧€閺?bash/sh/WSL閿涙稐濞囬悽?**busybox-w32 1.38.0**閿涘潉work/integration-98260/tools/busybox.exe`閿?娴犲懐鏁ゆ禍搴㈡拱閸︽媽顕㈠▔鏇燁梾閺屻儻绱氶敍?
```text
SH_N OK  run98260.sh
SH_N OK  target.sh
SH_N OK  run.sh
SH_N OK  clean.sh
SH_N OK  kernel_profiles.sh
SH_N OK  root_stage.sh
```

鐎瑰鍙忛幍顐ｅ伎閿?8260 閺傛澘顤冮柅鏄忕帆閿涘绱癭run98260.sh` 閺?adb/fastboot/flash/reboot/缂冩垹绮堕崨鎴掓姢閿?娑撳秴鍟?`/data/adb`閿涙矖[PARKED]` 閺冭泛鍟撻崥?boot 閺嶅洩顔囬獮璺轰粻濮濐澁绱漜red/rootd 鏉╂稓鈻?*娑?kill**閵?
## 4. 閺€鐟板З閺傚洣娆㈠〒鍛礋閿涘牏娴夌€?1.0.3閿涙稖绻冨銈嗗竴閺嬪嫬缂撴禍褏澧块敍?
閺傛澘顤冮敍?
```text
main/app/assets/98260/exploit-android-perf          (bd52314d閳? 66232 B)
main/app/assets/98260-6138/                         (6.12.38 闁倿鍘ゆ禍宀冪箻閸?4 娑?+ target.sh + SHA256SUMS.txt閿涘矁顫?鎼?)
main/app/assets/98260/exploit-android-perf-chain    (1cca5772閳? 66904 B)
main/app/assets/98260/exploit-android-key-ptr       (61bcb479閳? 80480 B)
main/app/assets/98260/pc98260-su                    (374bac50閳? 8584 B閿涘本绨崥?pc98260-su-client)
main/app/assets/98260/run98260.sh                   (fail-stop 闂冭埖顔岄張鐚寸礉29,288 B)
main/app/assets/98260/target.sh                     (閻╊喗鐖ｉ崘鍛壋/閸ㄥ褰?閸濆牆绗?閸忋劏鍏橀崝?gate 鐢悂鍣?
main/app/assets/98260/SHA256SUMS.txt                (6 妞ょ懓鎼辩敮宀嬬窗4 娴滃矁绻橀崚鏈电瑢 port 娑撯偓閼?+ 2 閼存碍婀?
tools/verify_98260_assets.py                        (缁傝崵鍤庣挧鍕獓/閺嶅洩顔囬弽锟犵崣閿涘苯宕熼崘鍛壋閺冄呭)
tools/verify_98260_dual.py                          (閸欏苯鍞撮弽姝岀カ娴?+ 闂嗗棙鍨氶弽锟犵崣)
README-98260.md                                     (闁炬崘鐭剧拠瀛樻/闂傘劍甯?婢惰精瑙﹂惍?閺堫亪鐛欑拠渚€銆?
MagicRoot-1.0.4-98260-experimental.apk              (娑撹姘︽禒姗堢礉鐟?鎼?)
docs/reference/apk-verify.md                        (verify_apk.py 閻㈢喐鍨氶惃鍕饯閹焦鐗庢宀冾唶瑜?
```

娣囶喗鏁奸敍?
```text
main/compose-app/app/build.gradle.kts               versionCode 9閳?0, versionName 1.0.4-98260-experimental閳?.0.5-98260-dual
main/app/AndroidManifest.xml                        versionCode 9閳?0, versionName 1.0.4-98260-experimental閳?.0.5-98260-dual
main/app/assets/run.sh                              娴犲懏鏌婃晶?MAGICROOT_CHAIN 閸掑棙娣抽崸妤嬬礄64560 閸樼喐绁︾粙瀣╃瑝閸旑煉绱?main/app/assets/kernel_profiles.sh                  娴犲懓鎷烽崝?select_chain_98260_profile()閿涘牅绗夐崝?select_kernel_profile閿?main/app/assets/clean.sh                            娴犲懓鎷烽崝?98260 閺勬儳绱″〒鍛倞閸ф绱欓崥?parked 閸?boot 閹锋帞绮峰〒鍛倞閿?main/app/pack_apk.py                                assets 閹垫挸瀵橀悽?os.listdir 閺€閫涜礋 os.walk 闁帒缍婇敍鍫熸暜閹?assets/98260/閿?main/app/src/com/aoki/magicroot/MainActivity.java   legacy 閸忔粌绨抽敍?8260 婢跺秹鈧顢?妫板嫭顥?闁劎璁?env/閹存劕濮涙稉宥嗙閻?main/compose-app/app/src/main/java/.../MainActivity.java
                                                    ASSETS_98260閵嗕焦瀵滈柧楣冨劥缂冩彃鍩?$D/98260閵嗕躬nv MAGICROOT_CHAIN/
                                                    MAGICROOT_ENABLE_98260/MAGICROOT_98260_PREFLIGHT閵?                                                    98260 閺堫亞鈥樼拋銈嗗珕缂佹繆绻嶇悰灞烩偓?8260 閹存劕濮涙稉宥堝殰閸斻劍绔婚悶鍡愨偓渚€顣╁Λ鈧Ο鈥崇础婢跺嫮鎮?main/compose-app/app/src/main/kotlin/.../UiState.kt 闁炬崘鐭鹃悩鑸碘偓?娴滃本顐肩涵顔款吇/妫板嫭顥呭鈧崗绛圭礄姒涙顓?64560閿?main/compose-app/app/src/main/kotlin/.../MiuixHost.kt 闁炬崘鐭鹃柅澶嬪閸楋紕澧?绾喛顓诲鍦崶閵?8260 閹绘劗銇氶妴涓U 瀵偓閸忓磭顩﹂悽銊ｂ偓?                                                    閹存劕濮涙い?98260-rootd 鐠囧瓨妲戦妴浣稿彠娴滃酣銆夐悧鍫熸拱/鐎圭偤鐛欓柧鎹愵嚛閺?tools/verify_apk.py                                 娣囶喖顦查弮?BakaSU syms 閸濆牆绗囬敍娑欐煀婢?98260 鐠у嫪楠?marker閿涙瞼I marker
README.md                                           閺嶅洦鏁?1.0.4-98260-experimental 鐎圭偤鐛欓柧?main/SHA256SUMS.txt / SHA256SUMS.txt                閹稿鏌婇弽鎴﹀櫢閺傛壆鏁撻幋鎰剁礄閺傜増鐖?202/202 閼奉亝鐗庢宀勨偓姘崇箖閿?```

## 5. 64560 姒涙顓荤捄顖氱窞娑撳秴褰夐惃鍕槈閹?
- `run.sh` 娑?1.0.3 閻?diff **閸欘亝婀佹稉鈧稉顏呮煀婢х偛娼?*閿涘潉@@ -230,6 +230,118 @@` 闂勫嫯绻庨敍澶涚窗
  `CHAIN=${MAGICROOT_CHAIN:-64560}`閿?4560/缁屽搫鈧偐娲块幒銉ㄦ儰閸掓澘甯ù浣衡柤閿?8260 閸掑棙娣抽崸?`exit 閸撳秳绗夌憴锔绢潾
  KASLR/ko_patch/permissive/cred/KSU`閵嗗倿绮拋銈夋，閹貉嶇窗

  ```text
  run.sh: CHAIN=${MAGICROOT_CHAIN:-64560}
  run.sh: if [ "${MAGICROOT_ENABLE_98260:-0}" != "1" ]; then FAIL=chain_98260_not_enabled
  MainActivity.java: MAGICROOT_CHAIN=<chain> / MAGICROOT_ENABLE_98260=<0|1> / MAGICROOT_98260_PREFLIGHT=<0|1>
  ```

- `kernel_profiles.sh` 閸?*鏉╄棄濮?*閸戣姤鏆?`select_chain_98260_profile()`閿涘潉@@ -221,3 +221,26 @@`閿涘绱?  `select_kernel_profile()` 娑撯偓鐞涘本婀弨鐧哥幢6.12.69-upstream 娴犲秵妫?profile閿涘潚ail-closed閿涘鈧?- `assets/clean.sh` 閸?*鏉╄棄濮?* 98260 閸ф绱檂@@ -32,6 +32,72 @@`閿涘绱濋崢?64560 濞撳懐鎮婇柅鏄忕帆娑撳秴褰夐妴?- 64560 閻?38 娑擃亣绁禍褍婀?APK 閸愬懍绗?1.0.3 濠ф劗鐖滈弽?`identical=38 content_diff=0`閵?- `pack_apk.py` 娴犲懏濡哥挧鍕獓闁秴宸婚弨閫涜礋闁帒缍婇敍娑滅翻閸戦缚鐭惧鍕矝閺?`assets/<relpath>`閿?4560 妞よ泛鐪扮挧鍕獓鐠侯垰绶炴稉宥呭綁閵?
## 6. 98260 闁炬崘顢戞稉鐑樻喅鐟曚緤绱欑€瑰鍙忛崗鎶芥暛閿?
- **姒涙顓婚崗鎶芥４ + 娴滃本顐肩涵顔款吇**閿涙瓗I 姒涙顓?64560閿涙稑鍨?98260 瀵湱鈥樼拋銈嗩攱閿涙稒婀涵顔款吇閺冭翰鈧苯绱戞慨瀣絹閺夊啨鈧秵瀚嗙紒婵囧⒔鐞涘被鈧?- **閻╊喗鐖ｉ梻銊﹀付**閿涘澁un98260.sh 閸氼垰濮╅崡铏梾閺屻儻绱氶敍姝歶name -r` 韫囧懘銆忕划鍓р€樼粵澶夌艾娑撱倓閲滈惄顔界垼閺嬪嫬缂撴稊瀣╃閿涘苯鎯侀崚?  `FAIL=kernel_unsupported`閿涙稑鑻熼幐?`uname -r` 闁瀚?`$D/98260`閿?.12.58閿涘鍨?  `$D/98260-6138`閿?.12.38閿涘绱遍崹瀣娇 MLY-AN00/BKQ-AN90 閸欘亜鎲＄拃锔肩幢upstream 6.12.69 娑撳秵妲搁崣顖濈箥鐞涘瞼娲伴弽鍥モ偓?- **tracefs/kprobe 妫板嫭甯?*閿涙艾鍨卞?閸掔娀娅庢稉鈧▎鈩冣偓?`p:magicroot_98260_probe_$$ __arm64_sys_getpid`閿?  婢惰精瑙?`FAIL=tracefs_kprobe_unwritable`閵?- **鐠у嫪楠囬崫鍫濈瑖**閿涙碍瀵滈幍鈧柅澶婂敶閺嶅摜娲拌ぐ鏇熺墡妤犲矉绱?.12.58閿? 妞ょ櫢绱?.12.38閿? 妞ょ櫢绱氶敍灞姐亼鐠?`FAIL=asset_hash`閵?- **闁劎璁茬捄顖氱窞**閿? 娑?exploit 婢跺秴鍩楅崚?`/data/local/tmp/`閿涘潷erf-chain 濠ф劗鐖滅涵顒傜椽閻?exec key-ptr閿涘绱?  闁劎璁查崥搴☆槻閺嶇鎼辩敮宀嬬幢鐟曞棛娲婂鎻掔摠閸︺劍鏋冩禒鑸垫鐠佹澘缍?`98260_DEPLOY_OVERWRITE` 娑撳孩鏌婇弮褍鎼辩敮灞烩偓?- **selinux 闂冭埖顔?*閿涙碍娓舵径?12 閸掑棝鎸撶粵澶婄窡 `getenforce=Permissive` 閹存牞绻樼粙瀣偓鈧崙鐚寸幢鏉╂稓鈻奸柅鈧崙杞扮稻闂?  Permissive 閳?`FAIL=selinux`閿涘潒xit 78閿涘绱濇稉宥呭晙缂佈呯敾 cred 闂冭埖顔岄敍鍧抋il-closed閿涘鈧?- **cred/fullcap/rootd 闂冭埖顔?*閿涙瓪setsid`閿涘牆娲栭柅鈧?nohup閿涘鎮楅崣鏉挎儙閸斻劊鈧?*娑撳秴顨?timeout閵嗕椒绗?kill**閿?  鏉烆喛顕?12 閸掑棝鎸撻敍鍫熺槨 3s flush cred.log + proof + parked + boot_id閿涘绱伴幋鎰缁斿宓?`98260_SUCCESS=1`
  楠炴湹绻氶悾?rootd閿涙矖[PARKED]`/`retain mappings` 閳?閸?`$D/.98260-parked`閿涘牆鑻熸径宥呭煑閸?  `/data/local/tmp/.magicroot-98260-parked`閿涘鎮?`FAIL=parked`閿涙稖绉撮弮鑸垫￥ proof 閳?`FAIL=proof`閵?- **閸?boot 闁插秷绐囨穱婵囧Б**閿涙俺鍓奸張顒€鎯庨崝銊ュ祮濡偓閺?parked 閺嶅洩顔囬惃?boot_id閿涙稑鎮?boot 閳?`FAIL=parked_retained`
  閿涘潏lean 娑撳秳绱板〒鍛存珟閿涙稑褰ч張澶愬櫢閸氼垰鎮楅弮?boot_id 閺嶅洩顔囬懛顏嗗姧婢惰鲸鏅ラ敍澶堚偓?- **clean.sh**閿涙碍妯夊蹇旂閻炲棙妞傞懟?parked 閺嶅洩顔囩仦鐐扮艾瑜版挸澧?boot閿涘矁绶崙?  `CLEAN_98260_REFUSED=parked_state_restart_required` 楠?*娑?kill**閿涘牓浼╅崗?init 閸ョ偞鏁?parked
  zombie 閳?timerqueue UAF 閳?panic閿涘绱遍崥锕€鍨?kill 閺堫剟鎽兼潻娑氣柤閵嗕礁鍨?socket閵嗕焦瀵滈崫鍫濈瑖閸掔娀娅庨柈銊ц閺傚洣娆㈤妴?  閸掔娀娅?`$D/98260`閵嗕椒绻氶悾?parked 閺嶅洩顔囬妴?- **閹存劕濮涢崚銈嗗祦**閿涘牏瀚粩瀣叀鐠囶澁绱濋棃鐐板敩閻炲棙瀵氶弽鍥风礆閿?  `uid=0(root)` + `CapEff/CapPrm/CapBnd=000001ffffffffff` + `Permissive` 閸氬本妞傞幋鎰彌閵?
## 7. 閺堫亪鐛欑拠渚€銆嶉敍鍫熸绾喛绔熼悾宀嬬礆

1. **閻喐婧€閹笛嗩攽閺堫亜浠?*閿涙碍婀伴悧鍫熸拱閺堫亜婀拋鎯ь槵娑撳﹨绻嶇悰宀嬬幢娑撳﹥鐖?upstream 閻楀牅绡冮崣顏勬躬 ADB shell閿涘澆id 2000閿涘鐛欑拠浣界箖閵?2. **Stellar/Shizuku shell 閸?*娑?tracefs/kprobe閵嗕垢erf_event_open閵嗕竸IO閵嗕共eyring 閸欘垵鎻幀褎婀惌?   閿涘湚onor 閻㈢喍楠?SELinux 缁涙牜鏆愰崣顖濆厴閺囩繝寮楅敍澶堚偓?3. `MEMSTART_PFN=0x80000` 閸嬪洩顔曢張顏嗩瀲缁捐儻鐦夌€圭儑绱?*6.12.58 娑?6.12.38 娑撱倓閲滈惄顔界垼閸у洭娓舵０鍕梾**閿涘绱版０鍕梾閻?`/proc/iomem` 娑?`@memstart_addr` kprobe
   閿涘潉p:pc98260ms/ms __arm64_sys_read ms=@memstart_addr:x64`閿涘矁袝閸?`cat /proc/self/stat`閿涘濮ら崨濠忕幢
   婢堕亶鍘ら崣顏勫閸?pcp-drain
   闂傘劍甯堕獮?fail-stop閵?4. `SLAB_OBJECTS=32` / `posix_timers` order/objs_per_slab 闂団偓鐠佹儳顦笟?   `/sys/kernel/slab/posix_timers` 閹?`--preflight`閿?2/32 owned slab + RCU閿涘鈥樼拋銈冣偓?5. 6.12.58 bootargs 閸?`page_poison=on`閵?.12.38 bootargs 娑撳秴鎯堥敍娑楄⒈閼板懘銆夐柌宥囨暏閺冭泛绨崸鍥ㄦ弓鐎圭偞绁撮敍?   `[PARKED]` 閸氬海娈戠€瑰鍙忛幁銏狀槻鐠囶厺绠熸笟婵婄闁插秴鎯庨妴?6. 閹存劕濮涢悳鍥﹁礋濮掑倻宸奸幀褝绱欐稉濠冪埗娑撳秳绻氱拠?100%閿涘绱濇稉?rootd 娴犲懎缍嬮崜宥呯磻閺堝搫鎳嗛張鐔告箒閺佸牄鈧?6b. 6.12.38 閻╊喗鐖ｇ亸姘￥娴犺缍嶇€圭偞婧€閺嶉攱婀伴敍鍫熸拱濞嗏€茬矌閹稿鏁ら幋鐤洣濮瑰倸浠涢棃娆愨偓渚€鈧倿鍘ゆ稉搴㈢€娲崣鐠囦緤绱氶妴?7. 98260 娴犲孩绨惍浣稿煂娴滃矁绻橀崚鍓佹畱闁插秶绱拠鎴︽付鐟?NDK r28c閿涙北ead 瀹告彃婀張顒佹簚閻?NDK r28c
   閿涘潉work/toolchain/ndk/android-ndk-r28c`閿涘绮犻柅鍌炲帳濠ф劗鐖滈柌宥呯紦楠?SHA256 闁藉顒?   閿涘潉port/98260-honor-61258/`閿涘绱濋張?APK 娴ｈ法鏁ょ拠銉┾偓鍌炲帳娴溠呭⒖閵?8. legacy APK 娴犲懎鍘规惔鏇熺€鐚寸礉闂堢偛褰傜敮鍐搼娴犻澧块敍鍫滅瑬 legacy UI 閻?64560 鐠у嫪楠囬崚妤勩€冩禒宥嗛儴閻劍妫悧鍫礉鐏炵偘绨弮銏℃箒闁鏆€閿涘鈧?
## 8. 婢跺秶骞囬崨鎴掓姢閿涘牊鎲崇憰渚婄礆

```powershell
$WI = "C:\Users\HourG\Documents\deepseek-harness\MagicRoot98260\work\integration-98260"
$env:GRADLE_USER_HOME = "C:\Users\HourG\Documents\deepseek-harness\MagicRoot98260\work\integration\build\gradle-home"
$env:MAGICROOT_KEYSTORE = "$WI\test-magicroot-1.0.4.keystore"
powershell -ExecutionPolicy Bypass -File `
  "MagicRoot-Enhanced-1.0.4-98260\main\app\build.ps1" `
  -Sdk C:\Users\HourG\Downloads\mly-fw\sdk `
  -Jdk C:\Users\HourG\Downloads\mly-fw\jdk25\jdk-25.0.4.1+1 `
  -Keystore $env:MAGICROOT_KEYSTORE -StorePass MagicRoot `
  -KeyAlias magicroot -KeyPass MagicRoot
python MagicRoot-Enhanced-1.0.4-98260\tools\verify_98260_assets.py
python MagicRoot-Enhanced-1.0.4-98260\tools\verify_98260_dual.py
python MagicRoot-Enhanced-1.0.4-98260\tools\verify_apk.py
```

濞村鐦?keystore閿涘牅绮庨弸鍕紦妤犲矁鐦夐敍宀勬姜閸欐垵绔风粵鎯ф倳閿涘绱癭work/integration/test-magicroot.keystore`
閿涘湧KCS12閿涘畮lias `magicroot`閿涘苯褰涙禒?`MagicRoot`閿涙稖鐦夋稊?DN `CN=MagicRoot Build Verification (cert sha256 4bf96225閳?75adb), OU=Integration, O=DSH, ...`閿涘鈧?
## 9. 鐎瑰鍙忔潏鍦櫕绾喛顓?
- 閺堫亣绻嶇悰?`adb`/`fastboot`閿涘本婀潻鐐村复閹靛婧€閿涘本婀€瑰顥?APK閿涘本婀?push 閺傚洣娆㈤敍灞炬弓閸掗攱婧€/閸掑棗灏幙宥勭稊閿?- `run98260.sh` 娑撳秴鎯?reboot/flash/缂冩垹绮堕崨鎴掓姢閿涘奔绗夐崘?`/data/adb`閿?- 98260 姒涙顓婚崗鎶芥４閵嗕線娓?UI 娴滃本顐肩涵顔款吇閵嗕浇顔曟径鍥︽櫠閸愬秵鐗庨惄顔界垼閸愬懏鐗虫稉搴ょカ娴溠冩惐鐢矉绱?- 婢惰精瑙︽稉鈧?fail-stop閿涘ARKED 娣囨繄鏆€閻滄澘婧€楠炲爼妯嗗銏犳倱 boot 闁插秷绐囬敍?- 閸樼喓娲拌ぐ?`MagicRoot-Enhanced-1.0.3/` 閸︺劍婀板▎鈥叉崲閸斺€冲閸氬骸娼?182/182 閸濆牆绗囨稉鈧懛娣偓?