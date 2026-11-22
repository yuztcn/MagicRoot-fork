# MagicRoot 6.6.118 Windows ADB 98260 测试链

适用设备：Honor AAK / MagicOS 10.0.0.175，内核
`6.6.118-android15-8-gf17133276a57-abogki518694926-4k`。
本工具**不刷 boot、不改系统分区、不 flash**；仅通过 adb 把测试文件推到
`/data/local/tmp/magic66118` 并执行 98260 UAF/rootd 链。

## 默认行为

- **默认不加载 SuSFS LKM**（只有显式 -SUSFS 才加载 6.6 SuSFS LKM guard）。
- 默认不加载 KernelSU（-Ksu none）。
- 每次运行自动创建 logs\<时间戳>\，采集设备信息、内核/profile、exploit、rootd、STP、KSU/SUSFS、dmesg、logcat、properties、modules、mounts、su paths，并打包 MagicRoot-66118-logs-<时间戳>.zip；失败也会采集。
- 日志输出不依赖手动 adb shell，便于直接把整包发给适配分析。

## 使用

```bat
run-66118.bat -Serial <设备序列号>
run-66118.bat -Serial <设备序列号> -Ksu official
run-66118.bat -Serial <设备序列号> -Ksu next -SUSFS
run-66118.bat -Serial <设备序列号> -Ksu sukisu
```

参数：

- `-Serial`：adb 序列号；省略则用第一台已授权设备。
- `-Ksu none|official|next|sukisu`：默认 `none`（只验证 98260 + STP clear）。
- `-SUSFS`：加载 6.6 预编译 SUSFS guard LKM。
- `-ForceMismatch`：跳过内核字符串检查（不推荐）。
- `-TimeoutSec`：rootd 等待秒数，默认 180。

## 资产

- `payload/exploit-android-key-ptr-66118`：6.6.118 静态适配 exploit。
- `payload/pc98260-su-66118`：rootd 客户端。
- `payload/stpclear`：STPS clear helper。
- `payload/ksu/`：官方 KernelSU 3.3.1、KernelSU-Next 3.4.2、SukiSU 4.2.1-r2 的
  android15-6.6 KO 与对应 ksud/ksuinit；官方 manager APK。
- `payload/susfs/`：SuSFS LKM（SUSFS4KSU-LKM）v2.3.0-r18.5 android15-6.6 guard LKM + loader；
  KernelSU-Next 的 6.6 SuSFS LKM guard 作为备选。

## 安全

- exploit 可能 panic；失败后重启设备再试。
- KSU/SuSFS LKM 加载为运行时 insmod，重启后消失；没有修改 boot/AVB。
- 64560 链未包含：当前 64560 二进制只支持 6.12，6.6.118 需要重新编译/适配，
  详见 `64560-66118-BLOCKERS.md`。
- 先在可恢复设备上验证；不要用于唯一生产机。

## su entry

PMX110 su_forward ELF 已放入 payload；product/bin/su 方案使用该 ELF，Termux 执行时不再因 shell_data_file 标签被拒绝。



## 序列号与日志

- -Serial 必须与 db devices 中的序列号完全一致；省略时自动取第一台 device 状态设备。
- 占位值（例如 A）会直接报错并列出可用序列号，不再进入内核检查。
- 日志采集使用单引号保留远端 $()，不会在 PowerShell 本机执行 getconf/pidof。
- 无设备或内核不匹配时仍会生成 logs/<timestamp>/ 和 MagicRoot-66118-logs-*.zip，但不会执行漏洞链。


## 已修复（20261028-213559 日志）

- db push 的进度输出写到 stderr，在 $ErrorActionPreference=Stop
  下被 PowerShell 当成终止错误，导致推完 exploit 后中止。
  现在 Adb() / SaveShell() / PullFile() 在原生 adb 调用期间临时切换
  为 Continue，db push 不再中断。
- 指定不存在的序列号（例如 A）会直接报错并列出可用设备；
  model/kernel 读取失败也会抛错，不再静默为空。
- 远端 $(getconf ...) / $(pidof ...) 使用单引号保留，不再被 PowerShell
  本机展开。


## 66260/66118 内核 build 限制

工具会读取 payload/profile-66118.json 的 kernel_release 并精确比对设备
uname -r：

`	ext
当前 profile 目标:
6.6.118-android15-8-gf17133276a57-abogki518694926-4k
`

如果设备是其他 6.6.118 build（例如本次日志中的
6.6.118-android15-8-g554929766a0d-abogki544555896-4k），工具会直接停止，
不再推送/运行 exploit，也不会等待 180 秒。

原因：66118 的 KASLR anchor、LINK_* 地址、geometry 是按 f171 构建静态派生的；
g554 的 KASLR 测量会得到未对齐值并拒绝运行：

`	ext
[slide] sample 1 unaligned ... -> reject
[slide] measurement did not converge, refusing to run
`

-ForceMismatch 只用于实验；不匹配 build 即使强制运行，通常也会在 KASLR 阶段失败。
如需支持 g554，需要提供该 build 的 boot.img/内核镜像，重新生成 profile、KASLR anchor、
syms 和静态适配二进制。

## 快速失败

即使使用 -ForceMismatch，工具也会在等待 rootd 时监视 exploit.log：

- 出现 measurement did not converge / 
efusing to run → 立即失败；
- exploit 进程连续退出且无 rootd socket → 立即失败；
- 不再盲等 -TimeoutSec。
