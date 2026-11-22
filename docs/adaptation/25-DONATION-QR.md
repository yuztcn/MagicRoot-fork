# 赞赏码入口

## 实现

- 资源：`main/app/res/drawable/donation_qrcode.jpg`（用户提供的赞赏码原图）
- 首页头部独立按钮：`赞赏`
- 弹窗：
  - 标题：`赞赏支持 MagicRoot`
  - 说明：扫码即可赞赏；感谢支持项目的持续维护。
  - 完整赞赏码图片（`ContentScale.Fit`，最大高度 420dp）
  - `关闭`
  - `保存到相册`
- About 页的捐赠卡片改为 `查看赞赏码` 入口，复用同一个弹窗。

## 保存到相册

使用 `MediaStore.Images`：

```text
DISPLAY_NAME = MagicRoot_donation_<timestamp>.png
MIME_TYPE    = image/png
RELATIVE_PATH= Pictures/MagicRoot
IS_PENDING   = 1 -> 0
```

保存的是当前显示的赞赏码（新码或旧码），保存成功 Toast：

```text
赞赏码已保存至 Pictures/MagicRoot
```

## 实测

- 首页“赞赏”按钮可独立点击；
- 弹窗完整展示赞赏码；
- 点击保存后生成：
  ```text
  /sdcard/Pictures/MagicRoot/MagicRoot_donation_<timestamp>.png
  ```
- 弹窗不会因保存而自动关闭，可继续查看或关闭。
- 不需要存储权限（Android 10+ MediaStore 自有写入）。
