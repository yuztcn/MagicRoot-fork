# 6.18 系内核 preflight load 上限

日期：2026-10-29

## 变更

`run.sh` 的 preflight load 默认上限：

```text
6.12.x       23
6.6.118-*    30
6.18.*       47
```

实现：

```sh
case "$(uname -r 2>/dev/null)" in
  6.6.118-*) PREFLIGHT_MAX_LOAD_DEFAULT=30 ;;
  6.18.*) PREFLIGHT_MAX_LOAD_DEFAULT=47 ;;
esac
```

显式环境变量仍优先：

```sh
MAGICROOT_PREFLIGHT_MAX_LOAD=47
```

## 原因

6.18 Honor 启动服务更多，idle load 常落在 35~45；旧默认 23 会让 98260 preflight 在系统已经可用时仍超时。

## 影响

- 只放宽 load 条件，不改变：
  - uptime settle 75s
  - `sys.boot_completed=1`
  - MemAvailable >= 1GB
  - preflight 总等待 150s
- 6.12 / 6.6.118 行为不变。
