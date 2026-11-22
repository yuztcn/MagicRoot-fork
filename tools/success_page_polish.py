#!/usr/bin/env python3
"""Success page polish:
- subtitle: 临时 root 已生效，重启需重新提权
- kernel version: split release vs git/build suffix (no orphan trailing "k")
- remove the now-duplicate bottom hint (subtitle already carries the message)
"""
from __future__ import annotations

from pathlib import Path

WS = Path(__file__).resolve().parent.parent
M = WS / "main/compose-app/app/src/main/kotlin/com/aoki/magicroot/MiuixHost.kt"
t = M.read_text(encoding="utf-8")


def sub(old: str, new: str):
    global t
    if old not in t:
        raise SystemExit("anchor missing: " + old[:80])
    t = t.replace(old, new, 1)


# 1. subtitle
sub('text = "临时 root 已生效，重启后自动失效",',
    'text = "临时 root 已生效，重启需重新提权",')

# 2. kernel version: structured two-line display
sub('''                Spacer(Modifier.height(6.dp))
                Text(
                    text = "内核版本",
                    fontSize = 12.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(
                    text = state.kernelVersion,
                    fontSize = 10.sp,
                    lineHeight = 14.sp,
                    color = MiuixTheme.colorScheme.onSurface,
                    modifier = Modifier.fillMaxWidth(),
                )''',
    '''                Spacer(Modifier.height(6.dp))
                Text(
                    text = "内核版本",
                    fontSize = 12.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    modifier = Modifier.fillMaxWidth(),
                )
                val kernelText = state.kernelVersion
                val gitSplit = kernelText.indexOf("-g")
                if (gitSplit > 0) {
                    // e.g. 6.12.58-android16-6 / g3a7ac1674240-abogki541502914-4k
                    Text(
                        text = kernelText.substring(0, gitSplit),
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = MiuixTheme.colorScheme.onSurface,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Text(
                        text = kernelText.substring(gitSplit + 1),
                        fontSize = 9.sp,
                        lineHeight = 13.sp,
                        fontFamily = FontFamily.Monospace,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        modifier = Modifier.fillMaxWidth(),
                    )
                } else {
                    Text(
                        text = kernelText,
                        fontSize = 10.sp,
                        lineHeight = 14.sp,
                        color = MiuixTheme.colorScheme.onSurface,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }''')

# 3. remove the duplicate bottom hint
sub('''                Spacer(Modifier.height(10.dp))
                Text(
                    text = "提示：临时 root 已生效；需要持久 root 或授权其他应用时，请打开 " +
                        state.ksuManagerLabel + " 管理器处理。",
                    fontSize = 10.sp,
                    lineHeight = 14.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
''', '')

M.write_text(t, encoding="utf-8", newline="\n")
print("patched SuccessPage")
