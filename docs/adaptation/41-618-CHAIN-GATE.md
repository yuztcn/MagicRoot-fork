# 6.18 98260 链路入口修复

日期：2026-10-29

## 失败日志

```text
FAIL=kernel_unsupported actual=6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k chain=98260
```

说明内核本身已被 `run98260.sh` 支持，但 `run.sh` 在更早的 profile 选择阶段就拒绝了。

## 根因

`kernel_profiles.sh` 的 98260 支持列表仍只有：

```text
6.12.58 / 6.12.38 / 6.12.23 / 6.12.38-YLP / 6.6.118 g554 / 6.6.118 f171
```

缺少：

```text
6.18.21 g928d1bb4f1d7
6.18.21 ge186062ea75f (BRM)
```

`run98260.sh` 内已有这两个 dispatch，但 `run.sh` 先调用
`select_chain_98260_profile`，未命中就输出 `kernel_unsupported`。

## 已修复

`kernel_profiles.sh` 新增：

```sh
CHAIN_98260_PROFILE_ID_61821="honor-61821-98260"
CHAIN_98260_KERNEL_61821="6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k"
CHAIN_98260_PROFILE_ID_61821BRM="honor-61821-brm-98260"
CHAIN_98260_KERNEL_61821BRM="6.18.21-android17-5-ge186062ea75f-abogki564062290-4k"
```

并加入 `CHAIN_98260_KERNELS` 和 `select_chain_98260_profile` 的 case。

`run.sh` 同步：

```text
chmod 755 .../98260-61821/* .../98260-61821-brm/*
HINT_SUPPORT 增加 6.18.21-g928 / 6.18.21-BRM
```

## 验证

独立脚本 source `kernel_profiles.sh` 后：

```text
OK release=6.18.21-...g928... profile=honor-61821-98260
OK release=6.18.21-...ge186... profile=honor-61821-brm-98260
OK release=6.6.118-...g554... profile=honor-g554-66118-98260
OK release=6.6.118-...f171... profile=honor-f171-66118-98260
OK release=6.12.58... profile=honor-61258-98260
```

APK 内已确认：

```text
assets/kernel_profiles.sh: CHAIN_98260_KERNEL_61821
assets/run.sh: 6.18.* -> PREFLIGHT_MAX_LOAD_DEFAULT=47
```

## 注意

- g928 profile 使用精确官方 KernelSU v3.3.1 资产；
- BRM ge186 仍是 rootd-only，`KSU_ENABLE=0`；
- 没有重建 6.6.118 测试包。
