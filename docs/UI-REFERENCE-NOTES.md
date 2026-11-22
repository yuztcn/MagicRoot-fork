# UI reference notes

The screenshots/video provided on 2026-11-02 were used as a UI/UX reference for
the home page and chain flow only.

Adopted:

- Home shows channel status, start action, model, kernel, and the free-app notice.
- Extra home setup buttons were removed; the start action opens the full flow.
- The flow is a linear page-by-page chain: 授权 → 管理器 → 提取 → 选项 → SuSFS → 提权.
- The bottom navigation is hidden while the flow is open.
- Deployment page includes 清理临时文件.
- Runtime options include 保留 su, 注入 SuSFS, and advanced parameters collapsed below.
- SuSFS page includes online update plus 选择本地 SuSFS .ko.
- Manager selection and component extraction are separate pages, matching the reference.

Explicitly not adopted:

- No Xiaomi 18 Pro Max / `6.18.21-g284297031c53` device or kernel adaptation was
  added.  The reference device/kernel in the screenshots is not part of this app's
  supported profile list.
- The reference app's Stellar branding is not adopted; this app keeps the
  Shizuku-only privileged channel.
