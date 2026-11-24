package com.aoki.magicroot

import android.content.ContentValues
import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.os.SystemClock
import android.provider.MediaStore
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.Image
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.snapshotFlow
import androidx.compose.runtime.withFrameNanos
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.animation.core.spring
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.width
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.positionChange
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.ClipEntry
import androidx.compose.ui.platform.LocalClipboard
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.view.WindowCompat
import kotlin.math.roundToInt
import androidx.compose.ui.unit.Density
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.foundation.layout.widthIn
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.SmallTitle
import top.yukonga.miuix.kmp.basic.CircularProgressIndicator
import top.yukonga.miuix.kmp.basic.LinearProgressIndicator
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.SmallTopAppBar
import top.yukonga.miuix.kmp.basic.Surface
import top.yukonga.miuix.kmp.basic.Switch
import top.yukonga.miuix.kmp.preference.OverlayDropdownPreference
import top.yukonga.miuix.kmp.preference.SwitchPreference
import top.yukonga.miuix.kmp.basic.TabRow
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import com.aoki.magicroot.glass.FloatingBottomBar
import com.aoki.magicroot.glass.FloatingBottomBarItem
import top.yukonga.miuix.kmp.blur.Backdrop
import top.yukonga.miuix.kmp.blur.isRuntimeShaderSupported
import top.yukonga.miuix.kmp.blur.blur
import top.yukonga.miuix.kmp.blur.colorControls
import top.yukonga.miuix.kmp.blur.drawBackdrop
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.blur.noiseDither
import top.yukonga.miuix.kmp.blur.rememberLayerBackdrop
import top.yukonga.miuix.kmp.blur.textureBlurEffect
import top.yukonga.miuix.kmp.blur.highlight.Highlight
import top.yukonga.miuix.kmp.theme.ColorSchemeMode
import top.yukonga.miuix.kmp.theme.ThemeColorSpec
import top.yukonga.miuix.kmp.theme.ThemeController
import top.yukonga.miuix.kmp.theme.ThemePaletteStyle
import top.yukonga.miuix.kmp.window.WindowDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.darkColorScheme
import top.yukonga.miuix.kmp.theme.lightColorScheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Installs the Compose/Miuix content into the existing Java controller activity. */
object MiuixHost {
    @JvmStatic
    fun install(activity: MainActivity) {
        activity.enableEdgeToEdge()
        val view = ComposeView(activity)
        activity.setContentView(view)
        view.setContent { MiuixRoot(activity, activity.ui) }
    }
}

@Composable
private fun MiuixRoot(activity: MainActivity, state: UiState) {
    val accentSeed = when (state.accentColor) {
        "jade" -> Color(0xFF18A57A)
        "violet" -> Color(0xFF8B5CF6)
        "sunset" -> Color(0xFFFF7A45)
        "rose" -> Color(0xFFE5487A)
        "graphite" -> Color(0xFF6B7280)
        "custom" -> Color(state.customAccent)
        else -> Color(0xFF3D7EFF) // Express
    }
    val paletteStyle = when (state.paletteStyle) {
        "monochrome" -> ThemePaletteStyle.Monochrome
        "neutral" -> ThemePaletteStyle.Neutral
        "vibrant" -> ThemePaletteStyle.Vibrant
        "expressive" -> ThemePaletteStyle.Expressive
        "fidelity" -> ThemePaletteStyle.Fidelity
        "content" -> ThemePaletteStyle.Content
        "rainbow" -> ThemePaletteStyle.Rainbow
        "fruit" -> ThemePaletteStyle.FruitSalad
        else -> ThemePaletteStyle.TonalSpot
    }
    val colorSpec = if (state.colorSpec == "2025") ThemeColorSpec.Spec2025
    else ThemeColorSpec.Spec2021
    val systemDark = isSystemInDarkTheme()
    val schemeMode = when {
        state.dynamicColor && state.themeMode == "light" -> ColorSchemeMode.MonetLight
        state.dynamicColor && state.themeMode == "dark" -> ColorSchemeMode.MonetDark
        state.dynamicColor -> ColorSchemeMode.MonetSystem
        state.themeMode == "dark" -> ColorSchemeMode.MonetDark
        state.themeMode == "light" -> ColorSchemeMode.MonetLight
        systemDark -> ColorSchemeMode.MonetDark
        else -> ColorSchemeMode.MonetLight
    }
    val systemAccent = remember {
        runCatching {
            Color(activity.getColor(android.R.color.system_accent1_500))
        }.getOrDefault(Color(0xFF6750A4))
    }
    val themeController = remember(
        schemeMode, state.dynamicColor, accentSeed, paletteStyle, colorSpec, systemAccent
    ) {
        if (state.dynamicColor) {
            // System Monet, re-expanded through the selected Material spec so
            // switching 2021 <-> 2025 actually changes the dynamic palette.
            ThemeController(
                colorSchemeMode = schemeMode,
                keyColor = systemAccent,
                colorSpec = colorSpec,
                paletteStyle = ThemePaletteStyle.TonalSpot,
            )
        } else {
            // Express / custom seed with the selected Material 3 spec + variant.
            ThemeController(
                colorSchemeMode = schemeMode,
                keyColor = accentSeed,
                colorSpec = colorSpec,
                paletteStyle = paletteStyle,
            )
        }
    }
    val configuration = LocalConfiguration.current
    val baseDensity = LocalDensity.current
    val adaptiveFontScale = when {
        configuration.screenWidthDp < 340 -> 0.84f
        configuration.screenWidthDp < 380 -> 0.92f
        configuration.screenWidthDp >= 700 -> 1.10f
        configuration.screenWidthDp >= 600 -> 1.06f
        else -> 1.0f
    }
    val adaptiveDensity = Density(
        density = baseDensity.density,
        fontScale = baseDensity.fontScale * adaptiveFontScale,
    )
    MiuixTheme(controller = themeController) {
      CompositionLocalProvider(LocalDensity provides adaptiveDensity) {
        val surfaceColor = MiuixTheme.colorScheme.surface
        val backdrop = rememberLayerBackdrop {
            drawRect(surfaceColor)
            drawContent()
        }
        val darkSystemBars = MiuixTheme.colorScheme.background.luminance() < 0.4f
        SideEffect {
            WindowCompat.getInsetsController(
                activity.window,
                activity.window.decorView,
            ).apply {
                isAppearanceLightStatusBars = !darkSystemBars
                isAppearanceLightNavigationBars = !darkSystemBars
            }
        }
        // Render the donation dialog before any page early-return.  AboutPage
        // returns from MiuixTheme, so a dialog emitted after that return was
        // never composed and the Settings/About 赞赏按钮 appeared dead.
        if (state.showDonation) {
            DonationDialog(onDismiss = { state.showDonation = false })
        }
        if (state.showFullLog) {
            BackHandler { state.showFullLog = false }
            FullLogPage(activity, state)
            return@CompositionLocalProvider
        }
        if (state.showSuccess) {
            BackHandler { activity.returnHome() }
            SuccessPage(activity, state)
            return@CompositionLocalProvider
        }
        LaunchedEffect(Unit) {
            activity.refreshInstalledManagers()
            activity.refreshInstalledApps()
        }
        BackHandler(enabled = state.mainTab != 0) { state.selectTab(0) }
        Scaffold(
            modifier = Modifier.fillMaxSize(),
            containerColor = MiuixTheme.colorScheme.background,
            contentWindowInsets = WindowInsets(0, 0, 0, 0),
            bottomBar = {
                if (!state.flowMode) {
                    Box(
                        modifier = Modifier.fillMaxWidth(),
                        contentAlignment = Alignment.BottomCenter,
                    ) {
                        MagicRootBottomBar(
                            state = state,
                            backdrop = backdrop,
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                }
            },
        ) { innerPadding ->
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .layerBackdrop(backdrop),
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding),
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .statusBarsPadding()
                            .clipToBounds(),
                    ) {
                        when (state.mainTab) {
                            0 -> HomePage(activity, state)
                            1 -> ToolsPage(activity, state)
                            else -> AboutPage(activity, state)
                        }
                        if (state.feedbackTitle.isNotEmpty()) {
                            // Home has a fixed bottom action bar, so its transient
                            // feedback uses the top card area.  Other pages keep
                            // the original bottom snackbar position.
                            val onHome = state.mainTab == 0
                            FeedbackBanner(
                                state,
                                Modifier
                                    .align(if (onHome) Alignment.TopCenter else Alignment.BottomCenter)
                                    .fillMaxWidth()
                                    .padding(horizontal = 16.dp)
                                    .padding(
                                        top = if (onHome) 8.dp else 0.dp,
                                        bottom = if (onHome) 0.dp else 12.dp,
                                    ),
                            )
                        }
                    }
                }
            }
        }
        if (state.showOptionsWarning) {
            OptionsChangeWarning(state)
        }
      }
    }
}

@Composable
private fun OptionsChangeWarning(state: UiState) {
    var dontShowAgain by remember(state.showOptionsWarning) { mutableStateOf(false) }
    WindowDialog(
        show = true,
        title = "运行参数修改提醒",
        summary = "运行选项和参数会直接影响提权链路，误改可能导致提权失败、模块异常或设备重启。请确认本次修改",
        onDismissRequest = { state.cancelOptionsChange() },
    ) {
        CompactToggle(
            title = "不再提示",
            subtitle = "确认后，后续修改不再弹出首次提示",
            checked = dontShowAgain,
            enabled = true,
            onCheckedChange = { dontShowAgain = it },
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(
                text = "取消",
                onClick = { state.cancelOptionsChange() },
            )
            Button(
                onClick = { state.confirmOptionsChange(dontShowAgain) },
                modifier = Modifier.weight(1f),
            ) {
                Text("确认修改", style = MiuixTheme.textStyles.button)
            }
        }
    }
}

@Composable
private fun GlassTabGlyph(
    index: Int,
    tint: Color,
    iconSize: androidx.compose.ui.unit.Dp = 20.dp,
) {
    Canvas(modifier = Modifier.size(iconSize)) {
        val w = size.width
        val h = size.height
        val stroke = Stroke(
            width = w * 0.105f,
            cap = StrokeCap.Round,
            join = StrokeJoin.Round,
        )
        val p = Path()
        when (index) {
            0 -> {
                p.moveTo(w * 0.12f, h * 0.46f)
                p.lineTo(w * 0.50f, h * 0.15f)
                p.lineTo(w * 0.88f, h * 0.46f)
                p.moveTo(w * 0.23f, h * 0.40f)
                p.lineTo(w * 0.23f, h * 0.84f)
                p.lineTo(w * 0.77f, h * 0.84f)
                p.lineTo(w * 0.77f, h * 0.40f)
                p.moveTo(w * 0.42f, h * 0.84f)
                p.lineTo(w * 0.42f, h * 0.62f)
                p.lineTo(w * 0.58f, h * 0.62f)
                p.lineTo(w * 0.58f, h * 0.84f)
                drawPath(p, tint, style = stroke)
            }
            1 -> {
                drawCircle(
                    color = tint,
                    radius = w * 0.25f,
                    center = center,
                    style = stroke,
                )
                drawCircle(
                    color = tint,
                    radius = w * 0.075f,
                    center = center,
                    style = Stroke(width = w * 0.07f),
                )
                for (i in 0 until 4) {
                    val angle = i * (Math.PI / 2.0)
                    val dx = kotlin.math.cos(angle).toFloat()
                    val dy = kotlin.math.sin(angle).toFloat()
                    drawLine(
                        tint,
                        start = center + androidx.compose.ui.geometry.Offset(dx * w * 0.31f, dy * h * 0.31f),
                        end = center + androidx.compose.ui.geometry.Offset(dx * w * 0.40f, dy * h * 0.40f),
                        strokeWidth = w * 0.10f,
                        cap = StrokeCap.Round,
                    )
                }
            }
            else -> {
                drawCircle(
                    color = tint,
                    radius = w * 0.37f,
                    center = center,
                    style = stroke,
                )
                drawCircle(
                    color = tint,
                    radius = w * 0.045f,
                    center = androidx.compose.ui.geometry.Offset(w * 0.5f, h * 0.32f),
                )
                drawLine(
                    tint,
                    start = androidx.compose.ui.geometry.Offset(w * 0.5f, h * 0.44f),
                    end = androidx.compose.ui.geometry.Offset(w * 0.5f, h * 0.70f),
                    strokeWidth = w * 0.105f,
                    cap = StrokeCap.Round,
                )
            }
        }
    }
}

@Composable
private fun MagicRootFlatBottomBar(state: UiState, modifier: Modifier = Modifier) {
    val tabs = listOf(
        Triple(0, "首页", 0),
        Triple(1, "工具", 1),
        Triple(2, "关于", 2),
    )
    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(MiuixTheme.colorScheme.surfaceContainer)
            .navigationBarsPadding(),
    ) {
        Box(
            Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(MiuixTheme.colorScheme.outline.copy(alpha = 0.20f)),
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .height(64.dp),
        ) {
            tabs.forEach { (glyphIndex, label, index) ->
                val selected = state.mainTab == index
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxHeight()
                        .clickable(enabled = !state.busy && !state.running) {
                            state.selectTab(index)
                        },
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center,
                ) {
                    Box(
                        modifier = Modifier
                            .width(48.dp)
                            .height(30.dp)
                            .clip(CircleShape)
                            .background(
                                if (selected) MiuixTheme.colorScheme.secondaryContainer
                                else Color.Transparent
                            ),
                        contentAlignment = Alignment.Center,
                    ) {
                        GlassTabGlyph(
                            index = glyphIndex,
                            tint = if (selected) MiuixTheme.colorScheme.onSecondaryContainer
                            else MiuixTheme.colorScheme.onSurfaceVariantSummary,
                            iconSize = 20.dp,
                        )                    }
                    Text(
                        text = label,
                        fontSize = 10.sp,
                        lineHeight = 12.sp,
                        color = if (selected) MiuixTheme.colorScheme.onSurface
                        else MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                }
            }
        }
    }
}

@Composable
private fun MagicRootBottomBar(
    state: UiState,
    backdrop: Backdrop,
    modifier: Modifier = Modifier,
) {
    if (!state.glassBottomBar || !isRuntimeShaderSupported()) {
        MagicRootFlatBottomBar(state, modifier)
        return
    }
    val tabs = listOf(
        Triple(0, "首页", 0),
        Triple(1, "工具", 1),
        Triple(2, "关于", 2),
    )
    val bottomPadding = WindowInsets.navigationBars
        .asPaddingValues()
        .calculateBottomPadding()
        .let { if (it != 0.dp) 8.dp + it else 28.dp }
    FloatingBottomBar(
        modifier = modifier.padding(
            start = 28.dp,
            end = 28.dp,
            bottom = bottomPadding,
        ),
        selectedIndex = state.mainTab,
        onSelected = { index ->
            if (!state.busy && !state.running) state.selectTab(index)
        },
        backdrop = backdrop,
        tabsCount = tabs.size,
        isBlurEnabled = true,
    ) { activateTab ->
        tabs.forEach { (glyphIndex, label, index) ->
            val selected = state.mainTab == index
            FloatingBottomBarItem(
                selected = selected,
                onClick = { activateTab(index) },
                modifier = Modifier.defaultMinSize(minWidth = 76.dp),
            ) {
                GlassTabGlyph(
                    index = glyphIndex,
                    tint = if (selected) MiuixTheme.colorScheme.onSurface
                    else MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    iconSize = 22.dp,
                )
                Text(
                    text = label,
                    fontSize = 11.sp,
                    lineHeight = 14.sp,
                    maxLines = 1,
                    softWrap = false,
                    overflow = TextOverflow.Visible,
                    color = if (selected) MiuixTheme.colorScheme.onSurface
                    else MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
            }
        }
    }
}

@Composable
private fun SectionLabel(text: String) {
    Text(
        text = text,
        fontSize = 13.sp,
        fontWeight = FontWeight.Medium,
        color = MiuixTheme.colorScheme.primary,
        modifier = Modifier.padding(start = 4.dp, top = 6.dp, bottom = 2.dp),
    )
}

private data class DangerSpec(
    val title: String,
    val summary: String,
    val action: () -> Unit,
)

@Composable
private fun ToolActionCard(
    title: String,
    subtitle: String,
    button: String,
    danger: Boolean = false,
    enabled: Boolean = true,
    onClick: () -> Unit,
) {
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(5.dp),
        ) {
            Text(
                title,
                style = MiuixTheme.textStyles.body1,
                color = if (danger) MiuixTheme.colorScheme.error
                else MiuixTheme.colorScheme.onSurface,
            )
            Text(
                subtitle,
                fontSize = 11.sp,
                lineHeight = 15.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            CompactTextButton(
                text = button,
                onClick = onClick,
                enabled = enabled,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Composable
private fun SuCheckRepairCard(activity: MainActivity, state: UiState) {
    val enabled = !state.busy && !state.running
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(5.dp),
        ) {
            Text(
                "SU 判定检查与修复",
                style = MiuixTheme.textStyles.body1,
                color = MiuixTheme.colorScheme.onSurface,
            )
            Text(
                "按 hisecd 的 su/magisk 路径与 ro.secure / ro.build.tags 判定；异常时可清除 STP root 判定。",
                fontSize = 11.sp,
                lineHeight = 15.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                CompactTextButton(
                    text = "检查 SU 判定",
                    onClick = { activity.checkSu() },
                    enabled = enabled,
                    modifier = Modifier.weight(1f),
                )
                CompactTextButton(
                    text = "修复判定",
                    onClick = { activity.repairSuDetection() },
                    enabled = enabled,
                    modifier = Modifier.weight(1f),
                )
            }
        }
    }
}

@Composable
private fun ToolsPage(activity: MainActivity, state: UiState) {
    var pending by remember { mutableStateOf<DangerSpec?>(null) }
    var dangerExpanded by remember { mutableStateOf(false) }
    var softFixStep by remember { mutableStateOf(0) }
    LazyColumn(
        modifier = Modifier
            .widthIn(max = 720.dp)
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 8.dp),
        contentPadding = PaddingValues(bottom = 96.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item { SectionLabel("常用") }
        item {
            ToolActionCard(
                title = "清理临时文件",
                subtitle = "只删除本工具的工作目录与外部 stage 缓存，不触碰 /data/adb。",
                button = "清理临时文件",
                enabled = !state.busy && !state.running,
            ) { activity.doClean() }
        }
        item {
            ToolActionCard(
                title = "修复平行空间",
                subtitle = "stop-user → STP Clear → 重新打开；与单独 STP Clear 分离。",
                button = "修复并打开平行空间",
                enabled = !state.busy && !state.running,
            ) { activity.fixParallelSpace() }
        }
        item {
            ToolActionCard(
                title = "导出上次运行日志",
                subtitle = "读取 /data/local/tmp/magic/run.log 并导出到 Download/MagicRoot；运行中不可导出。",
                button = "导出上次日志",
                enabled = !state.busy && !state.running,
            ) { activity.exportLastRunLog() }
        }
        item { SectionLabel("诊断与修复") }
        item {
            ToolActionCard(
                title = "Root 诊断",
                subtitle = "检查 uid / CapEff / SELinux / 存储 / 模块 Live / 管理器 / su。",
                button = if (state.diagnosticBusy) "诊断中…" else "运行 Root 诊断",
                enabled = !state.busy && !state.running && !state.diagnosticBusy,
            ) { activity.doRootDiagnosis() }
        }
        item {
            ToolActionCard(
                title = "STP Clear",
                subtitle = "清理 Honor STP/hisecd 判定，不停止、不启动用户。",
                button = "执行 STP Clear",
                enabled = !state.busy && !state.running,
            ) { activity.doStpClear() }
        }
        item {
            ToolActionCard(
                title = "STP 兼容配置",
                subtitle = "su_compat 默认开启；应用后关闭 su entry/su_compat，并在加载时以 force_feature=su_compat:0 禁用；KernelSU 自动加载保持开启，保留 rootd/socket；用于 full-cap STP Clear。",
                button = "应用 STP 配置",
                enabled = !state.busy && !state.running,
            ) { activity.applyStpCompatProfile() }
        }
        item {
            ToolActionCard(
                title = "停止 rootd 并清理 socket",
                subtitle = "仅停止 listener 子进程并删除 socket；PPID=1 父进程保留到重启。",
                button = "停止并清理",
                enabled = !state.busy && !state.running,
            ) { activity.stopRootdAndCleanSockets() }
        }
        item { SuCheckRepairCard(activity, state) }
        item { SectionLabel("管理器交接") }
        item {
            ToolActionCard(
                title = "管理器 KO 提取",
                subtitle = "6.12/6.6 提取匹配 KMI 的 LKM；6.1.x 也提取管理器 LKM，vermagic 精确匹配时优先加载，否则回退按内核适配的 CGA 模块。",
                button = "检查并提取",
                enabled = !state.busy && !state.running,
            ) { activity.checkManagerKo() }
        }
        item {
            ToolActionCard(
                title = "加载后修复 su",
                subtitle = "KSU 加载完成后重新建立 su entry；失败不会影响已获得的 root。",
                button = "修复 su entry",
                enabled = !state.busy && !state.running,
            ) { activity.repairSuEntryAfterLoad() }
        }
        item { SectionLabel("模块与隐藏") }
        item {
            ToolActionCard(
                title = "软重启修复（Zygisk / LSPosed）",
                subtitle = "先运行 KSU 模块 post-fs-data/services，再重启 zygote；不使用管理器 soft-reboot。" +
                        "执行时应用会关闭，约 30–60 秒恢复。",
                button = "执行软重启修复",
                enabled = !state.busy && !state.running,
            ) { softFixStep = 1 }
        }
        item { SusfsUpdateCard(activity, state) }
        item { SectionLabel("危险清理") }
        item {
            ToolActionCard(
                title = "危险清理",
                subtitle = "删除 /data/local/tmp 或 /data/adb 管理器数据；不可恢复。",
                button = if (dangerExpanded) "收起危险清理" else "展开危险清理",
                danger = true,
                enabled = !state.busy && !state.running,
            ) { dangerExpanded = !dangerExpanded }
        }
        if (dangerExpanded) {
            item {
                ToolActionCard(
                    title = "清理 /data/local/tmp",
                    subtitle = "删除全部内容（含其他工具文件）。检测到 parked 98260/rootd 时会拒绝执行。",
                    button = "清理 /data/local/tmp",
                    danger = true,
                    enabled = !state.busy && !state.running,
                    onClick = {
                        pending = DangerSpec(
                            "清理 /data/local/tmp？",
                            "这会删除该目录下全部内容，包括其他工具的文件，且不可恢复。",
                        ) { activity.doCleanTmp() }
                    },
                )
            }
            item {
                ToolActionCard(
                    title = "清理 /data/adb",
                    subtitle = "仅删除 ksu / ksud / modules / post-fs-data.d / service.d；会破坏管理器数据与模块。",
                    button = "清理 /data/adb 数据",
                    danger = true,
                    enabled = !state.busy && !state.running,
                    onClick = {
                        pending = DangerSpec(
                            "清理 /data/adb？",
                            "将删除管理器/模块目录。完成后可能需要重装管理器，且现有 root 配置会丢失。",
                        ) { activity.doCleanAdb() }
                    },
                )
            }
            item {
                ToolActionCard(
                    title = "清理 su 检测面（危险）",
                    subtitle = "su_compat 默认开启的检测面在这里一次性关闭；删除 MagicRoot su 入口，并尝试移除 /system/bin/su；会破坏 KSU su，rootd 保留。",
                    button = "清理 su 检测面",
                    danger = true,
                    enabled = !state.busy && !state.running,
                    onClick = {
                        pending = DangerSpec(
                            "清理 su 检测面？",
                            "将删除 /system/bin/su 等 su 入口并关闭 su_compat。KSU su 会失效，rootd 保留；重启后管理器可能恢复。",
                        ) { activity.cleanupSuDetectionSurface() }
                    },
                )
            }
        }
    }
    val p = pending
    if (p != null) {
        WindowDialog(
            show = true,
            title = p.title,
            summary = p.summary,
            onDismissRequest = { pending = null },
        ) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(text = "取消", onClick = { pending = null })
                Button(
                    onClick = {
                        pending = null
                        p.action()
                    },
                    modifier = Modifier.weight(1f),
                ) {
                    Text("确认执行", style = MiuixTheme.textStyles.button)
                }
            }
        }
    }
    if (softFixStep > 0) {
        val first = softFixStep == 1
        WindowDialog(
            show = true,
            title = if (first) "软重启修复？" else "再次确认软重启修复",
            summary = if (first)
                "将运行 KSU 模块生命周期并重启 zygote，让 Zygisk / LSPosed 重新加载。" +
                        "所有应用会关闭，但不会调用管理器 soft-reboot；已加入临时 root 收尸与模块重入防护。"
            else
                "这是第二次确认。点击“确认执行”后运行模块生命周期并重启 zygote；" +
                        "完成后打开 LSPosed 管理器确认“已激活”。",
            onDismissRequest = { softFixStep = 0 },
        ) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(text = "取消", onClick = { softFixStep = 0 })
                Button(
                    onClick = {
                        if (first) {
                            softFixStep = 2
                        } else {
                            softFixStep = 0
                            activity.runSoftRebootRepair()
                        }
                    },
                    modifier = Modifier.weight(1f),
                ) {
                    Text(if (first) "继续" else "确认执行", style = MiuixTheme.textStyles.button)
                }
            }
        }
    }
}

@Composable
private fun HomeQuickStart(
    activity: MainActivity,
    state: UiState,
    step: Int,
    labels: List<String>,
    onNext: () -> Unit,
) {
    val success = state.runResult == true
    val failed = state.runResult == false
    val preflight = state.preflightPassed
    val title = when {
        preflight == true -> "✓ 预检通过"
        preflight == false -> "✗ 预检未通过"
        success -> "✓ 越狱成功"
        failed -> "✗ 越狱失败"
        else -> "准备开始"
    }
    val buttonText = when {
        preflight != null -> "再次预检"
        success -> "打开 KernelSU"
        state.running -> "正在提权…"
        failed && step == labels.lastIndex -> "再次提权"
        step < labels.lastIndex -> "下一步：${labels[step + 1]}"
        else -> "开始提权"
    }
    Card(
        colors = CardDefaults.defaultColors(
            color = if (failed || preflight == false) MiuixTheme.colorScheme.errorContainer
            else if (success || preflight == true) MiuixTheme.colorScheme.secondaryContainer
            else MiuixTheme.colorScheme.surfaceContainerHigh,
        ),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    title,
                    fontSize = 20.sp,
                    lineHeight = 26.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = if (failed || preflight == false) MiuixTheme.colorScheme.onErrorContainer
                    else if (success || preflight == true) MiuixTheme.colorScheme.onSecondaryContainer
                    else MiuixTheme.colorScheme.onSurface,
                )
            }
            Text(
                "当前步骤：${labels[step]} · 全部步骤可在本页完成",
                fontSize = 11.sp,
                lineHeight = 16.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Button(
                onClick = {
                    if (success) {
                        activity.openKsuManager()
                    } else if (step < labels.lastIndex) {
                        onNext()
                    } else {
                        activity.startRun()
                    }
                },
                enabled = !state.busy && !state.running,
                colors = ButtonDefaults.buttonColorsPrimary(
                    contentColor = if (MiuixTheme.colorScheme.background.luminance() < 0.4f) {
                        MiuixTheme.colorScheme.onPrimary
                    } else Color.White,
                ),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(buttonText, style = MiuixTheme.textStyles.button)
            }
        }
    }
}

@Composable
private fun HomeDeviceInfoCard(state: UiState) {
    val model = state.deviceStatus.model.ifBlank { "unknown" }
    val kernel = state.kernelVersion.ifBlank { state.deviceStatus.kernel.ifBlank { "unknown" } }
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "机型",
                    fontSize = 13.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    modifier = Modifier.width(58.dp),
                )
                Text(
                    model,
                    fontSize = 14.sp,
                    color = MiuixTheme.colorScheme.onSurface,
                )
            }
            Column {
                Text(
                    "内核",
                    fontSize = 13.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
                Text(
                    kernel,
                    fontSize = 12.sp,
                    lineHeight = 18.sp,
                    fontFamily = FontFamily.Monospace,
                    color = MiuixTheme.colorScheme.onSurface,
                )
            }
        }
    }
}

@Composable
private fun FreeAppNoticeCard() {
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                "免费应用 禁止倒卖",
                style = MiuixTheme.textStyles.body1,
                color = MiuixTheme.colorScheme.onSurface,
            )
            Text(
                "如果你花钱获得了这个应用，请尽快申请退款并举报。",
                fontSize = 11.sp,
                lineHeight = 16.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
        }
    }
}

@Composable
private fun OneClickRootCard(activity: MainActivity, state: UiState, onClick: () -> Unit) {
    Card(
        colors = CardDefaults.defaultColors(color = MiuixTheme.colorScheme.surfaceContainerHigh),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(5.dp),
        ) {
            Text(
                "一键提权",
                fontSize = 17.sp,
                fontWeight = FontWeight.SemiBold,
                color = MiuixTheme.colorScheme.onSurface,
            )
            Text(
                "上次设置：${chainLabelOf(state.chain)} · ${state.ksuManagerLabel}",
                fontSize = 11.sp,
                lineHeight = 16.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Button(
                onClick = onClick,
                enabled = !state.busy,
                colors = ButtonDefaults.buttonColorsPrimary(
                    contentColor = if (MiuixTheme.colorScheme.background.luminance() < 0.4f) {
                        MiuixTheme.colorScheme.onPrimary
                    } else Color.White,
                ),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("一键提权", style = MiuixTheme.textStyles.button)
            }
        }
    }
}

@Composable
private fun HomePage(activity: MainActivity, state: UiState) {
    val screenConfig = LocalConfiguration.current
    val compactWidth = screenConfig.screenWidthDp < 360
    val logHeight = (if (state.running) 300 else 280)
        .coerceAtMost((screenConfig.screenHeightDp * 0.38f).roundToInt())
        .coerceAtLeast(160)
    val listState = rememberLazyListState()
    val scope = rememberCoroutineScope()
    // The step index (and the inline log flag) live in UiState, not in a
    // remember{} here.  Opening the fullscreen log replaces HomePage in the
    // composition (FullLogPage early-returns at the root); a remember{} step
    // was therefore reset to 0 on every return, which looked like "back exits
    // the final step and loses the progress panel".  The same applied to a tab
    // switch.  UiState outlives both.
    val step = state.homeStep
    val showLog = state.homeShowLog
    val labels = listOf("授权", "管理器", "提取", "选项", "SuSFS", "提权")
    val authorized = state.managerAuth.endsWith("已授权")
    fun goStep(index: Int) {
        state.homeStep = index.coerceIn(0, labels.lastIndex)
        scope.launch { listState.animateScrollToItem(0) }
    }
    val running = state.running
    LaunchedEffect(step) {
        // The transient "正在准备" banner belongs to earlier setup pages.
        if (step == labels.lastIndex) state.clearFeedback()
    }
    LaunchedEffect(state.feedbackTitle, step, state.busy, state.running) {
        // Keep the final run page clean while one-click auto-deployment is in
        // progress; failures after it stops are still allowed to show.
        if (step == labels.lastIndex && (state.busy || state.running)) {
            state.clearFeedback()
        }
    }
    val atRunStep = step == labels.lastIndex
    val buttonText = when {
        running -> "正在提权…"
        state.busy -> "处理中…"
        atRunStep && state.preflightPassed != null -> "再次预检"
        atRunStep && state.runResult == true -> "打开 KernelSU"
        atRunStep && state.runResult == false -> "再次提权"
        step == 0 && !authorized -> "授权 Shell"
        step == 0 -> "下一步：管理器"
        step == 1 -> "下一步：提取"
        step == 2 && !state.assetsDeployed -> "提取组件"
        step == 2 -> "下一步：选项"
        step == 3 -> "下一步：SuSFS"
        step == 4 -> "下一步：提权"
        else -> "开始提权"
    }
    val buttonAction: () -> Unit = {
        when {
            // Preflight is read-only; never jump to the manager as if root
            // succeeded.  Re-run the same read-only check.
            atRunStep && state.preflightPassed != null -> activity.startRun()
            // Only the final step may jump to the manager.  A successful run
            // while the user is back on an earlier step must continue the
            // step chain, not open KernelSU.
            atRunStep && state.runResult == true -> activity.openKsuManager()
            step == 0 && !authorized -> activity.doGrant()
            step == 0 -> goStep(1)
            step == 1 -> goStep(2)
            step == 2 && !state.assetsDeployed -> activity.doStage()
            step == 2 -> goStep(3)
            step == 3 -> goStep(4)
            step == 4 -> goStep(5)
            else -> activity.startRun()
        }
    }
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        LazyColumn(
            state = listState,
            modifier = Modifier
                .widthIn(max = 720.dp)
                .fillMaxSize()
                .padding(
                    horizontal = if (compactWidth) 8.dp else 12.dp,
                    vertical = 8.dp,
                ),
            contentPadding = PaddingValues(bottom = 108.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            item { HomeStatusDeck(state) }
            item { HomeDeviceInfoCard(state) }
            if (state.oneClickAvailable && !state.running && step < labels.lastIndex) {
                item {
                    OneClickRootCard(activity, state) {
                        // One-click is a shortcut to the same final step.  Show
                        // it immediately so progress/log are visible without
                        // stepping through the other cards.
                        state.homeStep = labels.lastIndex
                        state.homeShowLog = true
                        activity.oneClickRoot()
                    }
                }
            }
            item {
                InlineStepBar(labels = labels, current = step)
            }
            item {
                when (step) {
                    0 -> FlowStepCard(
                        index = "01",
                        title = "授权 Shell",
                        subtitle = "连接 Shizuku，并授予特权通道权限。",
                        done = authorized,
                    ) {
                        Text(
                            "状态：${state.managerAuth} · ${state.channelStatus}",
                            fontSize = 12.sp,
                            lineHeight = 18.sp,
                            color = if (authorized) MiuixTheme.colorScheme.primary
                            else MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                        Text(
                            if (authorized) "已就绪，点击底部按钮进入管理器选择。"
                            else "点击底部“授权 Shell”，在 Shizuku 弹窗中允许。",
                            fontSize = 11.sp,
                            lineHeight = 16.sp,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                    }
                    1 -> FlowStepCard(
                        index = "02",
                        title = "选择管理器",
                        subtitle = "先确定链路与管理器，再提取对应组件。",
                        done = state.ksuManagerPkg.isNotBlank(),
                    ) {
                        WizardManagerStep(state)
                    }
                    2 -> FlowStepCard(
                        index = "03",
                        title = "提取组件",
                        subtitle = "部署运行资产，并提取当前管理器的 ksud / LKM。",
                        done = state.assetsDeployed,
                    ) {
                        Text(
                            "目标目录 /data/local/tmp/magic；失败时可先清理临时文件。",
                            fontSize = 12.sp,
                            lineHeight = 18.sp,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                        TextButton(
                            text = "清理临时文件",
                            onClick = { activity.doClean() },
                            enabled = !state.busy,
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                    3 -> FlowStepCard(
                        index = "04",
                        title = "越狱选项",
                        subtitle = "选择当前链路需要的运行选项；高级参数默认折叠。",
                        done = true,
                    ) {
                        WizardRuntimeOptions(activity, state)
                    }
                    4 -> {
                        LaunchedEffect(Unit) { activity.refreshLocalSusfsState() }
                        FlowStepCard(
                            index = "05",
                            title = "SuSFS 模块",
                            subtitle = "可选：在线更新或导入本地模块；没有匹配模块时默认不加载。",
                            done = !state.susfsEnabled || state.susfsLocalModuleName.isNotBlank(),
                        ) {
                            SusfsModuleStep(activity, state)
                        }
                    }
                    else -> FlowStepCard(
                        index = "06",
                        title = "开始提权",
                        subtitle = "提权期间保持页面在前台；一次开机只建议打一发。",
                        done = state.runResult == true,
                    ) {
                        if (state.running) {
                            Text(
                                state.status,
                                fontSize = 13.sp,
                                lineHeight = 19.sp,
                                color = MiuixTheme.colorScheme.primary,
                            )
                            RunProgressCard(state)
                        } else if (state.busy) {
                            Text(
                                "正在准备提权环境…",
                                fontSize = 13.sp,
                                lineHeight = 19.sp,
                                color = MiuixTheme.colorScheme.primary,
                            )
                            LinearProgressIndicator(
                                progress = 0f,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(top = 6.dp),
                            )
                        } else {
                            Text(
                                "目标内核：${state.kernelVersion}",
                                fontSize = 12.sp,
                                lineHeight = 18.sp,
                                fontFamily = FontFamily.Monospace,
                                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                            )
                        }
                    }
                }
            }
            if (state.logText.isNotBlank() || state.running) {
                item {
                    TextButton(
                        text = if (showLog) "收起运行日志" else "查看运行日志",
                        onClick = { state.homeShowLog = !showLog },
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                if (showLog) {
                    item {
                        HomeLogPreview(
                            state,
                            Modifier
                                .fillMaxWidth()
                                .height((if (state.logText.isEmpty()) 148 else logHeight).dp),
                        )
                    }
                }
            }
        }
        Row(
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .fillMaxWidth()
                .padding(horizontal = if (compactWidth) 10.dp else 14.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            TextButton(
                text = "上一步",
                onClick = { if (step > 0) goStep(step - 1) },
                enabled = step > 0 && !state.busy && !state.running,
                modifier = Modifier.weight(1f),
            )
            Button(
                onClick = buttonAction,
                enabled = !state.busy && !state.running,
                colors = ButtonDefaults.buttonColorsPrimary(
                    contentColor = if (MiuixTheme.colorScheme.background.luminance() < 0.4f) {
                        MiuixTheme.colorScheme.onPrimary
                    } else Color.White,
                ),
                modifier = Modifier.weight(2f),
            ) {
                Text(buttonText, style = MiuixTheme.textStyles.button)
            }
        }
    }
}

@Composable
private fun InlineStepBar(labels: List<String>, current: Int) {
    Row(horizontalArrangement = Arrangement.spacedBy(3.dp)) {
        labels.forEachIndexed { index, label ->
            Box(
                modifier = Modifier
                    .weight(1f)
                    .background(
                        when {
                            index < current -> MiuixTheme.colorScheme.secondaryContainer
                            index == current -> MiuixTheme.colorScheme.primaryContainer
                            else -> MiuixTheme.colorScheme.surfaceContainerHigh
                        },
                        RoundedCornerShape(9.dp),
                    )
                    .padding(vertical = 7.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    label,
                    fontSize = 10.sp,
                    maxLines = 1,
                    color = when {
                        index < current -> MiuixTheme.colorScheme.onSecondaryContainer
                        index == current -> MiuixTheme.colorScheme.primary
                        else -> MiuixTheme.colorScheme.onSurfaceVariantSummary
                    },
                )
            }
        }
    }
}

@Composable
private fun SusfsModuleStep(activity: MainActivity, state: UiState) {
    if (!state.susfsSupported) {
        Text(
            "当前管理器不支持 SuSFS LKM，可直接下一步。",
            fontSize = 12.sp,
            lineHeight = 18.sp,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
        )
        return
    }
    if (state.susfsLocalModuleName.isNotBlank()) {
        Card(
            colors = CardDefaults.defaultColors(),
            insideMargin = PaddingValues(0.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(
                modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
                verticalArrangement = Arrangement.spacedBy(5.dp),
            ) {
                Text("SuSFS LKM", style = MiuixTheme.textStyles.body1)
                Text(
                    state.susfsLocalModuleName,
                    fontSize = 11.sp,
                    lineHeight = 16.sp,
                    fontFamily = FontFamily.Monospace,
                    color = MiuixTheme.colorScheme.onSurface,
                )
                Text(
                    "KMI ${state.susfsLocalModuleKmi} · ${state.susfsLocalModuleSource}",
                    fontSize = 11.sp,
                    color = MiuixTheme.colorScheme.primary,
                )
                Text(
                    if (state.susfsEnabled) {
                        "已检测到本地匹配模块，默认使用；无需重复下载。"
                    } else {
                        "已检测到本地匹配模块；SuSFS 当前未启用，下一步不会加载。"
                    },
                    fontSize = 11.sp,
                    lineHeight = 16.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
                if (state.susfsUpdateStatus.isNotEmpty()) {
                    Text(
                        state.susfsUpdateStatus,
                        fontSize = 11.sp,
                        lineHeight = 16.sp,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                }
                TextButton(
                    text = if (state.susfsUpdateBusy) "检查更新中…" else "检查 SuSFS LKM 更新",
                    onClick = { activity.updateSusfsLkm() },
                    enabled = !state.susfsUpdateBusy && !state.busy && !state.running,
                    modifier = Modifier.fillMaxWidth(),
                )
                TextButton(
                    text = "更换本地 SuSFS .ko",
                    onClick = { activity.pickSusfsLkm() },
                    enabled = !state.busy && !state.running,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    } else {
        Text(
            "未找到当前 KMI 的本地 SuSFS LKM，默认不加载；可直接下一步。",
            fontSize = 12.sp,
            lineHeight = 18.sp,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
        )
        SusfsUpdateCard(activity, state)
        TextButton(
            text = "选择本地 SuSFS .ko",
            onClick = { activity.pickSusfsLkm() },
            enabled = !state.busy && !state.running,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

@Composable
private fun FlowGuidePage(activity: MainActivity, state: UiState, onBack: () -> Unit) {
    var step by remember { mutableStateOf(0) }
    val authorized = state.managerAuth.endsWith("已授权")
    val compactWidth = LocalConfiguration.current.screenWidthDp < 360
    val steps = listOf("授权", "管理器", "提取", "选项", "SuSFS", "提权")
    val canNext = when (step) {
        0 -> authorized
        2 -> state.assetsDeployed
        else -> true
    }
    LazyColumn(
        modifier = Modifier
            .widthIn(max = 720.dp)
            .fillMaxWidth()
            .padding(horizontal = if (compactWidth) 10.dp else 14.dp),
        contentPadding = PaddingValues(top = 8.dp, bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                TextButton(text = "← 返回", onClick = onBack)
                Spacer(Modifier.weight(1f))
                Text(
                    "第 ${step + 1} / ${steps.size} 步",
                    fontSize = 13.sp,
                    fontFamily = FontFamily.Monospace,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(3.dp)) {
                steps.forEachIndexed { index, label ->
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .background(
                                when {
                                    index < step -> MiuixTheme.colorScheme.secondaryContainer
                                    index == step -> MiuixTheme.colorScheme.primaryContainer
                                    else -> MiuixTheme.colorScheme.surfaceContainerHigh
                                },
                                RoundedCornerShape(9.dp),
                            )
                            .padding(vertical = 7.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            label,
                            fontSize = 10.sp,
                            maxLines = 1,
                            color = when {
                                index < step -> MiuixTheme.colorScheme.onSecondaryContainer
                                index == step -> MiuixTheme.colorScheme.primary
                                else -> MiuixTheme.colorScheme.onSurfaceVariantSummary
                            },
                        )
                    }
                }
            }
        }
        item {
            when (step) {
                0 -> FlowStepCard(
                    index = "01",
                    title = "授权 Shell",
                    subtitle = "连接 Shizuku，并授予特权通道权限。",
                    done = authorized,
                ) {
                    Text(
                        "状态：${state.managerAuth} · ${state.channelStatus}",
                        fontSize = 12.sp,
                        lineHeight = 18.sp,
                        color = if (authorized) MiuixTheme.colorScheme.primary
                        else MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                    FlowPrimaryButton(
                        text = if (authorized) "重新检查授权" else "授权 Shell",
                        enabled = !state.busy,
                        onClick = { activity.doGrant() },
                    )
                }
                1 -> FlowStepCard(
                    index = "02",
                    title = "选择管理器",
                    subtitle = "先确定链路与管理器，再提取对应组件。",
                    done = state.ksuManagerPkg.isNotBlank(),
                ) {
                    WizardManagerStep(state)
                }
                2 -> FlowStepCard(
                    index = "03",
                    title = "提取组件",
                    subtitle = "部署运行资产，并提取当前管理器的 ksud / LKM。",
                    done = state.assetsDeployed,
                ) {
                    Text(
                        "目标目录 /data/local/tmp/magic；失败时可先清理临时文件。",
                        fontSize = 12.sp,
                        lineHeight = 18.sp,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                    FlowPrimaryButton(
                        text = if (state.assetsDeployed) "重新提取组件" else "提取组件",
                        enabled = !state.busy,
                        onClick = { activity.doStage() },
                    )
                    TextButton(
                        text = "清理临时文件",
                        onClick = { activity.doClean() },
                        enabled = !state.busy,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                3 -> FlowStepCard(
                    index = "04",
                    title = "越狱选项",
                    subtitle = "选择当前链路需要的运行选项；高级参数默认折叠。",
                    done = true,
                ) {
                    WizardRuntimeOptions(activity, state)
                }
                4 -> FlowStepCard(
                    index = "05",
                    title = "SuSFS 模块",
                    subtitle = "可选：在线更新、选择本地模块，或跳过。",
                    done = !state.susfsEnabled,
                ) {
                    if (!state.susfsSupported) {
                        Text(
                            "当前管理器不支持 SuSFS LKM，可跳过此步。",
                            fontSize = 12.sp,
                            lineHeight = 18.sp,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                    } else {
                        SusfsUpdateCard(activity, state)
                        TextButton(
                            text = "选择本地 SuSFS .ko",
                            onClick = { activity.pickSusfsLkm() },
                            enabled = !state.busy && !state.running,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        if (!state.susfsEnabled) {
                            Text(
                                "SuSFS 未启用，可下一步跳过。",
                                fontSize = 11.sp,
                                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                            )
                        }
                    }
                }
                else -> FlowStepCard(
                    index = "06",
                    title = "开始提权",
                    subtitle = "提权期间保持页面在前台；一次开机只建议打一发。",
                    done = state.runResult == true,
                ) {
                    if (state.running) {
                        Text(
                            state.status,
                            fontSize = 13.sp,
                            lineHeight = 19.sp,
                            color = MiuixTheme.colorScheme.primary,
                        )
                        RunProgressCard(state)
                    } else {
                        Text(
                            "目标内核：${state.kernelVersion}",
                            fontSize = 12.sp,
                            lineHeight = 18.sp,
                            fontFamily = FontFamily.Monospace,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                    }
                }
            }
        }
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                TextButton(
                    text = "上一步",
                    onClick = { if (step > 0) step-- },
                    enabled = step > 0 && !state.running,
                    modifier = Modifier.weight(1f),
                )
                Button(
                    onClick = {
                        if (step < 5) step++ else activity.startRun()
                    },
                    enabled = if (step < 5) canNext && !state.busy && !state.running
                    else !state.busy && !state.running,
                    modifier = Modifier.weight(1f),
                ) {
                    Text(
                        if (step < 5) "下一步：${steps[step + 1]}" else "开始提权",
                        style = MiuixTheme.textStyles.button,
                    )
                }
            }
        }
        if (state.logText.isNotBlank() || state.running) {
            item { SmallTitle(text = "运行日志") }
            item {
                HomeLogPreview(
                    state,
                    Modifier
                        .fillMaxWidth()
                        .height(if (state.running) 240.dp else 180.dp),
                )
            }
        }
    }
}

@Composable
private fun WizardManagerStep(state: UiState) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        HomeChain(state)
        HomeBackend(state)
    }
}

@Composable
private fun WizardRuntimeOptions(activity: MainActivity, state: UiState) {
    var advanced by remember { mutableStateOf(false) }
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text("基础运行参数", style = MiuixTheme.textStyles.body1)
            CompactTextButton(
                text = "恢复 su_compat / su entry 默认",
                onClick = { state.restoreSuDefaults() },
                enabled = !state.busy && !state.running,
                modifier = Modifier.fillMaxWidth(),
            )
            if (state.chain98260) {
                CompactToggle(
                    title = "自动加载 KernelSU",
                    subtitle = "默认开 · 加载失败时记录，不阻断 rootd",
                    checked = state.chain98260Ksu,
                    enabled = !state.busy && !state.running,
                    onCheckedChange = { state.update98260Ksu(it) },
                )
                CompactToggle(
                    title = "预检模式",
                    subtitle = "默认关 · 仅本次会话；只读检查，不执行 UAF/提权",
                    checked = state.chain98260Preflight,
                    enabled = !state.busy && !state.running,
                    onCheckedChange = { state.update98260Preflight(it) },
                )
                CompactTextButton(
                    text = "导入 boot.img 生成自适应配置",
                    onClick = { activity.pickAdaptiveBoot() },
                    enabled = !state.busy && !state.running,
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(
                    state.adaptiveProfileStatus,
                    fontSize = 10.sp,
                    lineHeight = 14.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
                CompactToggle(
                    title = "su_compat",
                    subtitle = "默认开 · 当前 boot 若曾被 force_feature 锁定，需重启后重新加载",
                    checked = state.suCompat,
                    enabled = !state.busy && !state.running && !state.skipFsuid,
                    onCheckedChange = { state.updateSuCompat(it) },
                )
                if (state.kernelVersion.startsWith("6.1.")) {
                    val restoredCga =
                        state.kernelVersion.startsWith("6.1.157-android14-11-g2646292297b1") ||
                            state.kernelVersion.startsWith("6.1.157-android14-11-gaaa383620ebf")
                    Text(
                        if (restoredCga) {
                            "此内核使用恢复版 CGA：支持传统 SU、内核级卸载和 SELinux 隐藏；初始化失败会保留 su_lkm 回退并记录 CGA-FEATURES。"
                        } else {
                            "6.1.x CGA 模块没有内核 su_compat，管理器的“传统 SU 命令支持”会显示不支持。su 由 su_lkm 用户态入口提供，MagicRoot 会自动修补 Termux 的 su 搜索列表。"
                        },
                        fontSize = 10.sp,
                        lineHeight = 14.sp,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                }
                CompactToggle(
                    title = "保留 su",
                    subtitle = "为旧应用提供 su 入口；STP 场景才会与 su_compat 一起关闭",
                    checked = state.suEntry,
                    enabled = !state.busy && !state.running && !state.skipFsuid,
                    onCheckedChange = { state.updateSuEntry(it) },
                )
                CompactToggle(
                    title = "保留 rootd/socket（STP）",
                    subtitle = "默认关 · 成功后保留 rootd/socket；仅 STP Clear 需要",
                    checked = state.keepRootdForStp,
                    enabled = !state.busy && !state.running,
                    onCheckedChange = { state.updateKeepRootdForStp(it) },
                )
            } else {
                CompactToggle(
                    title = "保留 su",
                    subtitle = "为旧应用提供 su 入口；关闭可减少 check-su 检测面（KSU 的 /system/bin/su 仍可能命中）",
                    checked = state.suEntry,
                    enabled = !state.busy && !state.running && !state.skipFsuid,
                    onCheckedChange = { state.updateSuEntry(it) },
                )
                CompactToggle(
                    title = "su_compat",
                    subtitle = "默认开 · 独立特性，不绑定 su entry；STP 场景建议与 su entry 一起关闭",
                    checked = state.suCompat,
                    enabled = !state.busy && !state.running && !state.skipFsuid,
                    onCheckedChange = { state.updateSuCompat(it) },
                )
                CompactToggle(
                    title = "ADB Root",
                    subtitle = "默认关 · 开启后请勿关闭 USB 调试",
                    checked = state.adbRoot,
                    enabled = !state.busy && !state.running,
                    onCheckedChange = { state.updateAdbRoot(it) },
                )
                CompactToggle(
                    title = "完成后清理临时文件",
                    subtitle = "默认开 · 仅 KSU root 可用时自动清理",
                    checked = state.autoCleanTemp,
                    enabled = !state.busy && !state.running,
                    onCheckedChange = { state.updateAutoCleanTemp(it) },
                )
                CompactToggle(
                    title = "保留 rootd/socket（STP）",
                    subtitle = "默认关 · 成功后不清理 rootd/socket，供 full-cap STP Clear 使用；需要时用工具页停止",
                    checked = state.keepRootdForStp,
                    enabled = !state.busy && !state.running,
                    onCheckedChange = { state.updateKeepRootdForStp(it) },
                )
                CompactToggle(
                    title = "allow shell",
                    subtitle = "默认开 · 加载期参数",
                    checked = state.allowShell,
                    enabled = !state.busy && !state.running,
                    onCheckedChange = { state.updateAllowShell(it) },
                )
            }
            SusfsRuntimeOptions(state)
        }
    }
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            TextButton(
                text = if (advanced) "收起高级运行参数" else "展开高级运行参数",
                onClick = { advanced = !advanced },
                modifier = Modifier.fillMaxWidth(),
            )
            if (advanced) {
                if (state.chain98260) {
                    Text("98260 调优", fontSize = 11.sp,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary)
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        Button(
                            onClick = { state.cycle98260Attempts() },
                            enabled = !state.busy && !state.running,
                            modifier = Modifier.weight(1f),
                        ) { Text("尝试 ${state.chain98260Attempts}", fontSize = 11.sp) }
                        Button(
                            onClick = { state.cycle98260ChurnRounds() },
                            enabled = !state.busy && !state.running,
                            modifier = Modifier.weight(1f),
                        ) { Text("churn ${state.chain98260ChurnRounds}", fontSize = 11.sp) }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        Button(
                            onClick = { state.cycle98260ChurnPerCpu() },
                            enabled = !state.busy && !state.running,
                            modifier = Modifier.weight(1f),
                        ) { Text("每CPU ${state.chain98260ChurnPerCpu}", fontSize = 11.sp) }
                        Button(
                            onClick = { state.cycle98260WaitCap() },
                            enabled = !state.busy && !state.running,
                            modifier = Modifier.weight(1f),
                        ) { Text("等待 ${state.chain98260WaitCap}s", fontSize = 11.sp) }
                    }
                } else {
                    ParameterDropdown(
                        title = "SELinux permissive",
                        summary = "目标进程 permissive 值",
                        values = listOf(16, 24, 32),
                        selectedValue = state.victimPerm,
                        enabled = !state.busy && !state.running,
                        onSelected = { state.updateVictimPerm(it) },
                    )
                    ParameterDropdown(
                        title = "fsuid",
                        summary = "目标进程 fsuid",
                        values = listOf(16, 24, 32),
                        selectedValue = state.victimFsuid,
                        enabled = !state.busy && !state.running,
                        onSelected = { state.updateVictimFsuid(it) },
                    )
                    ParameterDropdown(
                        title = "cred",
                        summary = "目标进程 cred 值",
                        values = listOf(8, 12, 16, 24, 32),
                        selectedValue = state.victimCred,
                        enabled = !state.busy && !state.running,
                        onSelected = { state.updateVictimCred(it) },
                    )
                }
                CompactToggle(
                    title = "kernel_umount",
                    subtitle = "默认开",
                    checked = state.kernelUmount,
                    enabled = !state.busy && !state.running,
                    onCheckedChange = { state.updateKernelUmount(it) },
                )
                CompactToggle(
                    title = "selinux_hide",
                    subtitle = "默认开",
                    checked = state.selinuxHide,
                    enabled = !state.busy && !state.running,
                    onCheckedChange = { state.updateSelinuxHide(it) },
                )
                CompactToggle(
                    title = "real_cred",
                    subtitle = if (state.credMode == "real")
                        "开：real-cred + 独立 cap + direct-finit"
                    else
                        "关：fake-cred + rootd + 管理器 late-load",
                    checked = state.credMode == "real",
                    enabled = !state.busy && !state.running,
                    onCheckedChange = { state.updateCredMode(if (it) "real" else "fake") },
                )
                CompactToggle(
                    title = "跳过 PREFLIGHT",
                    subtitle = "已移除 PREFLIGHT 负载/开机等待限制",
                    checked = state.skipPreflight,
                    enabled = !state.busy && !state.running,
                    onCheckedChange = { state.updateSkipPreflight(it) },
                )
                TextButton(
                    text = "通过 SAF 选择自定义 .ko",
                    onClick = { activity.pickCustomKo() },
                    enabled = !state.busy && !state.running,
                )
                Text(
                    if (state.customKoPath.isNotEmpty()) state.customKoPath
                    else "未选择自定义 .ko",
                    fontSize = 10.sp,
                    lineHeight = 14.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
                CompactToggle(
                    title = "加载自定义 .ko",
                    subtitle = "校验 ELF/vermagic 后按目标 vermagic 加载",
                    checked = state.customKoEnabled,
                    enabled = state.customKoPath.isNotEmpty() && !state.busy && !state.running,
                    onCheckedChange = { state.updateCustomKoEnabled(it) },
                )
                TextButton(
                    text = "恢复默认参数",
                    onClick = { state.resetRunDefaults() },
                    enabled = !state.busy && !state.running,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
}

@Composable
private fun SusfsRuntimeOptions(state: UiState) {
    CompactToggle(
        title = "注入 SuSFS（实验性）",
        subtitle = if (!state.susfsSupported) {
            "Official KernelSU 不支持；其它管理器可按 KMI 尝试"
        } else if (state.susfsEnabled) {
            "加载 SuSFS LKM；缺失/失败只记录，不阻断"
        } else {
            "关闭 · 开启后按 KMI 匹配尝试加载"
        },
        checked = state.susfsEnabled && state.susfsSupported,
        enabled = !state.busy && !state.running && state.susfsSupported,
        onCheckedChange = { state.updateSusfs(it) },
    )
    if (state.susfsEnabled && state.susfsSupported) {
        CompactToggle(
            title = "SuSFS 保护模式",
            subtitle = "只在 rootd 阶段预加载，KSU 后不再二次加载",
            checked = state.susfsProtectMode,
            enabled = !state.busy && !state.running,
            onCheckedChange = { state.updateSusfsProtectMode(it) },
        )
    }
}

@Composable
private fun FlowStepCard(
    index: String,
    title: String,
    subtitle: String,
    done: Boolean,
    content: @Composable () -> Unit,
) {
    Card(
        colors = CardDefaults.defaultColors(
            color = if (done) MiuixTheme.colorScheme.secondaryContainer
            else MiuixTheme.colorScheme.surfaceContainerHigh,
        ),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(30.dp)
                        .background(
                            if (done) MiuixTheme.colorScheme.primaryContainer
                            else MiuixTheme.colorScheme.surfaceContainer,
                            CircleShape,
                        ),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        index,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = if (done) MiuixTheme.colorScheme.primary
                        else MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                }
                Column(modifier = Modifier.padding(start = 9.dp).weight(1f)) {
                    Text(
                        title,
                        fontSize = 15.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = if (done) MiuixTheme.colorScheme.onSecondaryContainer
                        else MiuixTheme.colorScheme.onSurface,
                    )
                    Text(
                        subtitle,
                        fontSize = 10.sp,
                        lineHeight = 14.sp,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                }
                Text(
                    if (done) "已完成" else "待完成",
                    fontSize = 10.sp,
                    color = if (done) MiuixTheme.colorScheme.primary
                    else MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
            }
            content()
        }
    }
}

@Composable
private fun FlowPrimaryButton(text: String, enabled: Boolean, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        enabled = enabled,
        colors = ButtonDefaults.buttonColorsPrimary(
            contentColor = if (MiuixTheme.colorScheme.background.luminance() < 0.4f) {
                MiuixTheme.colorScheme.onPrimary
            } else Color.White,
        ),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(text, style = MiuixTheme.textStyles.button)
    }
}

@Composable
private fun HomeStatusDeck(state: UiState) {
    val connected = state.channelStatus != "未连接"
    val authorized = state.managerAuth.endsWith("已授权")
    val running = state.running
    val success = state.runResult == true
    val failed = state.runResult == false
    val preflight = state.preflightPassed
    val title = when {
        running -> "正在越狱"
        preflight == true -> "预检通过"
        preflight == false -> "预检未通过"
        success -> "越狱成功"
        failed -> "越狱失败"
        connected -> "${state.channelStatus} 已连接"
        else -> "通道未连接"
    }
    val detail = when {
        running -> state.status
        preflight == true -> "只读检查完成，未执行提权"
        preflight == false -> "只读检查未通过，请查看日志"
        success -> "提权完成"
        failed -> "请查看日志后重试"
        connected && authorized -> "特权通道就绪，可以开始越狱"
        connected -> "已连接，等待管理器授权"
        else -> "请启动 Shizuku"
    }
    val container = when {
        failed || preflight == false -> MiuixTheme.colorScheme.errorContainer
        success || preflight == true -> MiuixTheme.colorScheme.secondaryContainer
        running -> MiuixTheme.colorScheme.tertiaryContainer
        connected && authorized -> MiuixTheme.colorScheme.secondaryContainer
        connected -> MiuixTheme.colorScheme.tertiaryContainer
        else -> MiuixTheme.colorScheme.surfaceContainerHigh
    }
    // Miuix's *Container / on*Container pair is not guaranteed to keep a
    // readable contrast in every dynamic theme.  Pick the text color from the
    // actual container luminance instead of trusting the paired token.
    val content = statusContentColor(container)
    Card(
        colors = CardDefaults.defaultColors(color = container),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Row(verticalAlignment = Alignment.Top) {
                StatusEmblem(
                    color = content,
                    // A connected Shizuku/authorized channel is a positive
                    // state too: draw the check inside the ring instead of
                    // leaving the left circle hollow.
                    working = connected || success || running,
                    warning = failed || (!running && !connected),
                    modifier = Modifier
                        .padding(top = 2.dp)
                        .size(30.dp),
                )
                Spacer(Modifier.width(10.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        title,
                        fontSize = 20.sp,
                        lineHeight = 26.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = content,
                    )
                    Text(
                        detail,
                        fontSize = 12.sp,
                        color = content.copy(alpha = 0.78f),
                    )
                }
            }
            Text(
                "通道 ${state.channelStatus} · ${state.managerAuth}",
                fontSize = 11.sp,
                color = content.copy(alpha = 0.65f),
            )
        }
    }
}

private fun statusContentColor(background: Color): Color =
    if (background.luminance() > 0.45f) Color(0xFF141414) else Color.White

@Composable
private fun StatusEmblem(
    color: Color,
    working: Boolean,
    warning: Boolean,
    modifier: Modifier = Modifier,
) {
    Canvas(modifier = modifier) {
        val stroke = 2.2.dp.toPx()
        val r = size.minDimension / 2f - stroke
        drawCircle(
            color = color,
            radius = r,
            style = Stroke(stroke),
        )
        if (working) {
            drawLine(
                color = color,
                start = androidx.compose.ui.geometry.Offset(size.width * 0.28f, size.height * 0.52f),
                end = androidx.compose.ui.geometry.Offset(size.width * 0.44f, size.height * 0.68f),
                strokeWidth = stroke,
            )
            drawLine(
                color = color,
                start = androidx.compose.ui.geometry.Offset(size.width * 0.44f, size.height * 0.68f),
                end = androidx.compose.ui.geometry.Offset(size.width * 0.74f, size.height * 0.34f),
                strokeWidth = stroke,
            )
        } else if (warning) {
            drawLine(
                color = color,
                start = androidx.compose.ui.geometry.Offset(size.width * 0.5f, size.height * 0.28f),
                end = androidx.compose.ui.geometry.Offset(size.width * 0.5f, size.height * 0.58f),
                strokeWidth = stroke,
            )
            drawCircle(
                color = color,
                radius = stroke * 0.72f,
                center = androidx.compose.ui.geometry.Offset(size.width * 0.5f, size.height * 0.74f),
            )
        }
    }
}

@Composable
private fun MiniTag(
    text: String,
    background: Color,
    foreground: Color,
) {
    Text(
        text = text,
        fontSize = 10.sp,
        lineHeight = 14.sp,
        color = foreground,
        modifier = Modifier
            .clip(CircleShape)
            .background(background)
            .padding(horizontal = 7.dp, vertical = 2.dp),
    )
}

@Composable
private fun HomeHeader(state: UiState) {
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp)) {
            Row(verticalAlignment = Alignment.Top) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "MagicRoot",
                        style = MiuixTheme.textStyles.footnote1,
                        color = MiuixTheme.colorScheme.primary,
                    )
                    Spacer(Modifier.height(2.dp))
                    Text(
                        text = "零特权提权链路",
                        style = MiuixTheme.textStyles.title4,
                        color = MiuixTheme.colorScheme.onSurface,
                    )
                }
                Column(horizontalAlignment = Alignment.End) {
                    StatusPill(
                        text = when {
                            state.running -> "运行中"
                            state.busy -> "处理中"
                            else -> "就绪"
                        },
                        color = when {
                            state.running -> MiuixTheme.colorScheme.primaryContainer
                            state.busy -> MiuixTheme.colorScheme.secondaryContainer
                            else -> MiuixTheme.colorScheme.tertiaryContainer
                        },
                    )
                    Text(
                        text = "关于",
                        style = MiuixTheme.textStyles.footnote1,
                        color = MiuixTheme.colorScheme.primary,
                        modifier = Modifier
                            .clickable { state.showAbout = true }
                            .padding(horizontal = 8.dp, vertical = 8.dp),
                    )
                }
            }
            Spacer(Modifier.height(8.dp))
            Text(
                text = if (state.chain98260) {
                    "CVE-2026-98260 · 默认链 · ${state.status}"
                } else {
                    "CVE-2026-64560 · ${state.ksuManagerLabel} LKM · ${state.status}"
                },
                style = MiuixTheme.textStyles.body2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = "链路 ${chainLabelOf(state.chain)} · 内核 ${state.kernelVersion}",
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun RunProgressCard(state: UiState) {
    LaunchedEffect(state.running, state.runStartedAt) {
        while (state.running && state.runStartedAt > 0) {
            state.runElapsedSec = ((SystemClock.elapsedRealtime() - state.runStartedAt) / 1000L).toInt()
            delay(500)
        }
    }
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "提权进度",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Medium,
                    color = MiuixTheme.colorScheme.onSurface,
                )
                Spacer(Modifier.weight(1f))
                Text(
                    text = formatElapsed(state.runElapsedSec),
                    fontSize = 13.sp,
                    fontFamily = FontFamily.Monospace,
                    color = MiuixTheme.colorScheme.onSurface,
                )
            }
            Text(
                text = state.runStage,
                fontSize = 11.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            LinearProgressIndicator(
                progress = state.runProgress.coerceIn(0, 100) / 100f,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 6.dp),
            )
            Text(
                text = if (state.running) "${state.runProgress}% · 运行中" else "${state.runProgress}% · 已结束",
                fontSize = 10.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
        }
    }
}

private fun formatElapsed(seconds: Int): String {
    val s = seconds.coerceAtLeast(0)
    val h = s / 3600
    val m = (s % 3600) / 60
    val sec = s % 60
    return if (h > 0) {
        String.format("%d:%02d:%02d", h, m, sec)
    } else {
        String.format("%02d:%02d", m, sec)
    }
}

@Composable
private fun CompactTextButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    TextButton(
        text = text,
        onClick = onClick,
        modifier = modifier.clip(RoundedCornerShape(18.dp)),
        enabled = enabled,
        minHeight = 40.dp,
        insideMargin = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
        textStyle = MiuixTheme.textStyles.footnote1,
    )
}

@Composable
private fun HomeSetupActions(activity: MainActivity, state: UiState) {
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            val largeText = LocalDensity.current.fontScale >= 1.5f
            if (largeText) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    CompactTextButton(
                        text = "授权 Shell",
                        onClick = { activity.doGrant() },
                        enabled = !state.busy,
                        modifier = Modifier.weight(1f),
                    )
                    CompactTextButton(
                        text = "部署资产",
                        onClick = { activity.doStage() },
                        enabled = !state.busy,
                        modifier = Modifier.weight(1f),
                    )
                }
                CompactTextButton(
                    text = "清理临时文件",
                    onClick = { activity.doClean() },
                    enabled = !state.busy,
                    modifier = Modifier.fillMaxWidth(),
                )
            } else {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    CompactTextButton(
                        text = "授权 Shell",
                        onClick = { activity.doGrant() },
                        enabled = !state.busy,
                        modifier = Modifier.weight(1f),
                    )
                    CompactTextButton(
                        text = "部署资产",
                        onClick = { activity.doStage() },
                        enabled = !state.busy,
                        modifier = Modifier.weight(1f),
                    )
                    CompactTextButton(
                        text = "清理临时",
                        onClick = { activity.doClean() },
                        enabled = !state.busy,
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        }
    }
}

@Composable
private fun HomeStartAction(activity: MainActivity, state: UiState) {
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(
                "路线：连接 → 管理器 → 配置 → 执行",
                fontSize = 10.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Button(
                onClick = { activity.startRun() },
                enabled = !state.busy && !state.running,
                colors = ButtonDefaults.buttonColorsPrimary(
                    contentColor = if (MiuixTheme.colorScheme.background.luminance() < 0.4f) {
                        MiuixTheme.colorScheme.onPrimary
                    } else {
                        Color.White
                    },
                ),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("开始提权", style = MiuixTheme.textStyles.button)
            }
        }
    }
}

@Composable
private fun RouteStrip(state: UiState) {
    val steps = listOf("01 连接", "02 管理器", "03 配置", "04 执行")
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        steps.forEachIndexed { index, label ->
            val active = if (state.running) index == 3 else index == 0
            Box(
                modifier = Modifier
                    .weight(1f)
                    .background(
                        if (active) MiuixTheme.colorScheme.primaryContainer
                        else MiuixTheme.colorScheme.surfaceContainerHigh,
                        RoundedCornerShape(10.dp),
                    )
                    .padding(vertical = 6.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    label,
                    fontSize = 10.sp,
                    color = if (active) MiuixTheme.colorScheme.primary
                    else MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
            }
        }
    }
}

@Composable
private fun StepHeader(index: String, title: String, subtitle: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            modifier = Modifier
                .size(26.dp)
                .background(MiuixTheme.colorScheme.primaryContainer, RoundedCornerShape(13.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Text(index, fontSize = 10.sp, color = MiuixTheme.colorScheme.primary)
        }
        Column(modifier = Modifier.padding(start = 8.dp)) {
            Text(title, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
            Text(
                subtitle,
                fontSize = 10.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
        }
    }
}

@Composable
private fun ParallelSpaceCard(activity: MainActivity, state: UiState) {
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = "Root 后平行空间被 STP 拦截？",
                style = MiuixTheme.textStyles.body1,
                color = MiuixTheme.colorScheme.onSurface,
            )
            Text(
                text = "自动识别平行空间 User → 清理 STP → 重新打开，不 stop 用户。需要 root/rootd 后端。",
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            CompactTextButton(
                text = "修复并打开平行空间",
                onClick = { activity.fixParallelSpace() },
                enabled = !state.busy && !state.running,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Composable
private fun HomeChain(state: UiState) {
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp)) {
            Text(
                text = if (state.chain98260) "98260 · 默认链" else "64560 · 备用链",
                style = MiuixTheme.textStyles.body1,
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(2.dp))
            Text(
                text = if (state.chain98260) {
                    "rootd + KernelSU/管理器，成功后仅当前开机有效"
                } else {
                    "需精确内核匹配，脚本 fail-closed"
                },
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            if (state.chain98260) {
                Spacer(Modifier.height(2.dp))
                Text(
                    text = "支持 6.12.x / 6.6.118 / 6.1.x（6.1.99 / 6.1.128 / 6.1.157）；6.18.21 / 6.1.x 仅走 98260 profile",
                    style = MiuixTheme.textStyles.footnote2,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
            }
            val kernel = state.kernelVersion.ifBlank { state.deviceStatus.kernel }
            val supports64560 = !(kernel.contains("6.18.21") || kernel.contains("6.1."))
            if (!supports64560 && state.chain98260) {
                Spacer(Modifier.height(2.dp))
                Text(
                    text = "当前内核不支持 64560 链路，切换已置灰",
                    style = MiuixTheme.textStyles.footnote2,
                    color = MiuixTheme.colorScheme.error,
                )
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
            ) {
                CompactTextButton(
                    text = if (state.chain98260) "切回 64560" else "使用 98260",
                    onClick = {
                        state.requestChainChange(if (state.chain98260) "64560" else "98260")
                    },
                    enabled = !state.busy && !state.running &&
                        !(state.chain98260 && !supports64560),
                )
            }
        }
    }
}

@Composable
private fun ParameterDropdown(
    title: String,
    summary: String,
    values: List<Int>,
    selectedValue: Int,
    enabled: Boolean,
    onSelected: (Int) -> Unit,
) {
    OverlayDropdownPreference(
        title = title,
        summary = summary,
        items = values.map(Int::toString),
        selectedIndex = values.indexOf(selectedValue).coerceAtLeast(0),
        enabled = enabled,
        onSelectedIndexChange = { index -> onSelected(values[index]) },
    )
}

@Composable
private fun HomeParameters(state: UiState, onPickKo: () -> Unit) {
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 9.dp)) {
            if (!state.paramsExpanded) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = "自定义运行参数默认折叠；修改前需确认",
                        style = MiuixTheme.textStyles.footnote2,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        modifier = Modifier.weight(1f),
                    )
                    CompactTextButton(
                        text = "展开",
                        onClick = { state.expandParams() },
                        enabled = !state.busy && !state.running,
                    )
                }
            } else {
            Spacer(Modifier.height(2.dp))
            CompactToggle(
                title = "确认修改运行参数",
                subtitle = "默认关闭；开启后才允许修改 64560 / 98260 运行参数",
                checked = state.editRunParams,
                enabled = !state.busy && !state.running,
                onCheckedChange = { state.updateEditRunParams(it) },
            )
            ParameterDropdown(
                title = "SELinux permissive",
                summary = "目标进程 permissive 值（16 / 24 / 32）",
                values = listOf(16, 24, 32),
                selectedValue = state.victimPerm,
                enabled = state.editRunParams && !state.busy && !state.running,
                onSelected = { value ->
                    state.requestOptionsChange { state.updateVictimPerm(value) }
                },
            )
            ParameterDropdown(
                title = "fsuid",
                summary = "目标进程 fsuid（16 / 24 / 32）",
                values = listOf(16, 24, 32),
                selectedValue = state.victimFsuid,
                enabled = state.editRunParams && !state.busy && !state.running,
                onSelected = { value ->
                    state.requestOptionsChange { state.updateVictimFsuid(value) }
                },
            )
            ParameterDropdown(
                title = "cred",
                summary = "目标进程 cred 值（8 / 12 / 16 / 24 / 32）",
                values = listOf(8, 12, 16, 24, 32),
                selectedValue = state.victimCred,
                enabled = state.editRunParams && !state.busy && !state.running,
                onSelected = { value ->
                    state.requestOptionsChange { state.updateVictimCred(value) }
                },
            )
                TextButton(
                    text = "通过 SAF 选择 .ko 文件",
                    onClick = onPickKo,
                    enabled = !state.busy && !state.running,
                )
                Text(
                    text = if (state.customKoPath.isNotEmpty()) state.customKoPath
                    else "未选择自定义 .ko（请用 SAF 选择）",
                    fontSize = 10.sp,
                    lineHeight = 14.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
                CompactToggle(
                    title = "加载自定义 .ko",
                    subtitle = "先校验 ELF/vermagic，默认改写并校验目标 vermagic 后加载",
                    checked = state.customKoEnabled,
                    enabled = state.customKoPath.isNotEmpty() && !state.busy && !state.running,
                    onCheckedChange = { state.updateCustomKoEnabled(it) },
                )
            if (state.chain98260 && state.paramsExpanded) {
                Spacer(Modifier.height(4.dp))
                CompactToggle(
                    title = "预检模式",
                    subtitle = "默认关 · 仅本次会话；只读检查，不执行 UAF/提权",
                    checked = state.chain98260Preflight,
                    enabled = state.editRunParams && !state.busy && !state.running,
                    onCheckedChange = { state.update98260Preflight(it) },
                )
                CompactToggle(
                    title = "自动加载 KernelSU",
                    subtitle = "默认开启；仅调试时关闭（不影响 rootd 验收）",
                    checked = state.chain98260Ksu,
                    enabled = state.editRunParams && !state.busy && !state.running,
                    onCheckedChange = { state.update98260Ksu(it) },
                )
                Text(
                    text = "98260 运行参数",
                    fontSize = 10.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Button(
                        onClick = { state.cycle98260Attempts() },
                        enabled = state.editRunParams && !state.busy && !state.running,
                        modifier = Modifier.weight(1f),
                    ) { Text("尝试 ${state.chain98260Attempts}", maxLines = 1, fontSize = 11.sp) }
                    Button(
                        onClick = { state.cycle98260ChurnRounds() },
                        enabled = state.editRunParams && !state.busy && !state.running,
                        modifier = Modifier.weight(1f),
                    ) { Text("churn ${state.chain98260ChurnRounds}", maxLines = 1, fontSize = 11.sp) }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Button(
                        onClick = { state.cycle98260ChurnPerCpu() },
                        enabled = state.editRunParams && !state.busy && !state.running,
                        modifier = Modifier.weight(1f),
                    ) { Text("每CPU ${state.chain98260ChurnPerCpu}", maxLines = 1, fontSize = 11.sp) }
                    Button(
                        onClick = { state.cycle98260WaitCap() },
                        enabled = state.editRunParams && !state.busy && !state.running,
                        modifier = Modifier.weight(1f),
                    ) { Text("等待 ${state.chain98260WaitCap}s", maxLines = 1, fontSize = 11.sp) }
                }
                Text(
                    text = "98260 已验证 6.12.58 / 6.12.58b、6.6.118 g554/f171；6.1.157 g264 已实机，其余 6.1.x 为静态适配；开始提权时按精确 uname -r 选择，脚本 fail-closed",
                    fontSize = 10.sp,
                    lineHeight = 14.sp,
                    color = MiuixTheme.colorScheme.primary,
                )
            }
                CompactTextButton(
                    text = "收起运行参数",
                    onClick = { state.collapseParams() },
                    enabled = !state.busy && !state.running,
                )
            }
        }
    }
}

@Composable
private fun ManagerRow(
    info: ManagerInfo,
    selected: Boolean,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                if (selected) MiuixTheme.colorScheme.primaryContainer
                else Color.Transparent,
                RoundedCornerShape(14.dp),
            )
            .clickable(enabled = enabled && info.installed, onClick = onClick)
            .padding(horizontal = 8.dp, vertical = 9.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    info.label,
                    fontSize = 13.sp,
                    fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
                    color = MiuixTheme.colorScheme.onSurface,
                )
                if (selected) {
                    Text(
                        " 当前",
                        fontSize = 10.sp,
                        color = MiuixTheme.colorScheme.primary,
                    )
                }
            }
            Text(
                info.pkg,
                fontSize = 10.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            val installedText = buildString {
                append("本机 ")
                append(info.version.ifBlank { "未知版本" })
                if (info.versionCode.isNotBlank()) {
                    append(" · ")
                    append(info.versionCode)
                }
            }
            Text(
                if (info.installed) installedText else "未安装",
                fontSize = 10.sp,
                color = if (info.installed) MiuixTheme.colorScheme.primary
                else MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
        }
        StatusPill(
            if (info.installed) "已安装" else "未安装",
            if (info.installed) MiuixTheme.colorScheme.primaryContainer
            else MiuixTheme.colorScheme.surfaceContainerHigh,
        )
    }
}

@Composable
private fun HomeBackend(state: UiState) {
    var showOther by remember { mutableStateOf(false) }
    var otherQuery by remember { mutableStateOf("") }
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(7.dp),
        ) {
            Text("选择管理器", style = MiuixTheme.textStyles.body1)
            Text(
                "默认只使用本机已安装管理器，现场提取其 ksud / LKM；内置资产仅作兜底，不再单列预选分类。",
                fontSize = 10.sp,
                lineHeight = 14.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            if (state.installedManagers.isEmpty()) {
                Text(
                    "正在扫描本地管理器…",
                    fontSize = 11.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
            }
            state.installedManagers.forEach { info ->
                ManagerRow(
                    info = info,
                    selected = info.pkg == state.ksuManagerPkg,
                    enabled = !state.busy && !state.running,
                ) {
                    if (info.installed) state.selectInstalledManager(info)
                }
            }
            TextButton(
                text = "选择其他已安装应用",
                onClick = { showOther = true },
                enabled = !state.busy && !state.running,
                modifier = Modifier.fillMaxWidth(),
            )
            val currentManager = state.installedManagers.firstOrNull {
                it.pkg == state.ksuManagerPkg
            } ?: state.installedManagers.firstOrNull {
                it.flavor == state.ksuFlavor
            }
            val currentInstalled = currentManager?.installed
                ?: state.deviceStatus.managerInstalled
            val currentVersion = currentManager?.version?.takeIf { it.isNotBlank() }
                ?: state.deviceStatus.managerVersion
            val currentVersionCode = currentManager?.versionCode?.takeIf { it.isNotBlank() }
                ?: state.deviceStatus.managerVersionCode
            val currentDetail = buildString {
                if (currentVersion.isNotBlank()) append(" · ").append(currentVersion)
                if (currentVersionCode.isNotBlank()) {
                    append(" · ").append(currentVersionCode)
                }
            }
            Text(
                "当前包：${state.ksuManagerPkg} · " +
                    if (currentInstalled) "已安装$currentDetail" else "未安装",
                fontSize = 10.sp,
                color = if (currentInstalled)
                    MiuixTheme.colorScheme.primary
                else MiuixTheme.colorScheme.error,
            )
        }
    }
    if (showOther) {
        val ctx = LocalContext.current
        WindowDialog(
            show = true,
            title = "选择本地管理器",
            summary = "仅作为 userspace/ksud 来源；LKM 模板仍使用当前 Flavor。未知管理器的模块兼容性需自行确认。",
            onDismissRequest = { showOther = false },
        ) {
            BasicTextField(
                value = otherQuery,
                onValueChange = { otherQuery = it },
                singleLine = true,
                textStyle = TextStyle(
                    color = MiuixTheme.colorScheme.onSurface,
                    fontSize = 13.sp,
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .background(
                        MiuixTheme.colorScheme.surfaceContainerHigh,
                        RoundedCornerShape(10.dp),
                    )
                    .padding(horizontal = 10.dp, vertical = 8.dp),
            )
            val filtered = state.installedApps.filter {
                otherQuery.isBlank() ||
                    it.label.contains(otherQuery, ignoreCase = true) ||
                    it.pkg.contains(otherQuery, ignoreCase = true)
            }
            LazyColumn(modifier = Modifier.heightIn(max = 300.dp)) {
                items(filtered.size) { index ->
                    val app = filtered[index]
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                state.selectOtherManager(app.pkg)
                                showOther = false
                                Toast.makeText(ctx, "已选择 ${app.label}", Toast.LENGTH_SHORT).show()
                            }
                            .padding(horizontal = 4.dp, vertical = 9.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(app.label, fontSize = 13.sp)
                            Text(
                                app.pkg,
                                fontSize = 10.sp,
                                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                            )
                        }
                    }
                }
            }
            TextButton(text = "取消", onClick = { showOther = false }, modifier = Modifier.fillMaxWidth())
        }
    }
}

@Composable
private fun HomeLogPreview(state: UiState, modifier: Modifier = Modifier) {
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(10.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
            ) {
                CompactTextButton(
                    text = "全屏查看",
                    onClick = { state.showFullLog = true },
                )
            }
            val logScroll = rememberScrollState()
            LaunchedEffect(state.logText) {
                withFrameNanos { }
                logScroll.scrollTo(logScroll.maxValue)
            }
            LaunchedEffect(logScroll) {
                snapshotFlow { logScroll.maxValue }.collectLatest { max ->
                    if (max > 0) logScroll.scrollTo(max)
                }
            }
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .background(
                        MiuixTheme.colorScheme.surfaceContainer,
                        RoundedCornerShape(8.dp),
                    )
                    .verticalScroll(logScroll)
                    .padding(8.dp),
                contentAlignment = if (state.logText.isEmpty()) Alignment.Center else Alignment.TopStart,
            ) {
                Text(
                    text = state.logText.ifEmpty { "暂无日志。部署资产后开始提权" },
                    fontSize = 9.5.sp,
                    lineHeight = 14.sp,
                    fontFamily = FontFamily.Monospace,
                    color = if (state.logText.isEmpty())
                        MiuixTheme.colorScheme.onSurfaceVariantSummary
                    else
                        MiuixTheme.colorScheme.onSurface,
                )
            }
        }
    }
}

private fun latestKeyLogText(log: String): String {
    if (log.isEmpty()) return log
    // Copy a contiguous recent block, not a bag of marker lines.  The old
    // filter kept only lines containing FAIL/KSU/PARALLEL and dropped every
    // line that explained them, which produced fragment-only copies.
    val maxChars = 16000
    val lines = log.lineSequence()
        .map { it.trimEnd() }
        .filter { it.isNotBlank() }
        .toList()
    if (lines.isEmpty()) return ""

    val starts = listOf(
        "PARALLEL_FIX_BEGIN",
        "提权任务已启动",
        "98260_CHAIN_BEGIN",
        "CHAIN_98260_PRE",
        "CHAIN_BEGIN",
    )
    val startIndex = lines.indexOfLast { line ->
        starts.any { marker -> line.contains(marker, ignoreCase = true) }
    }
    val from = if (startIndex >= 0) startIndex else (lines.size - 160).coerceAtLeast(0)
    val block = lines.subList(from, lines.size)

    val selected = ArrayDeque<String>()
    var used = 0
    for (line in block.asReversed()) {
        val additional = if (selected.isEmpty()) line.length else line.length + 1
        if (used + additional > maxChars) break
        selected.addFirst(line)
        used += additional
    }
    val body = selected.joinToString("\n")
    return if (selected.size < block.size) {
        "[日志过长，已截取最近 ${body.length} 字符]\n$body"
    } else {
        body
    }
}

@Composable
private fun FullLogPage(activity: MainActivity, state: UiState) {
    val logScroll = rememberScrollState()
    val scope = rememberCoroutineScope()
    LaunchedEffect(state.logText) {
        withFrameNanos { }
        logScroll.scrollTo(logScroll.maxValue)
    }
    LaunchedEffect(logScroll) {
        snapshotFlow { logScroll.maxValue }.collectLatest { max ->
            if (max > 0) logScroll.scrollTo(max)
        }
    }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MiuixTheme.colorScheme.background)
            .statusBarsPadding()
            .navigationBarsPadding(),
    ) {
        SmallTopAppBar(
            title = "运行日志",
            subtitle = "当前内核 ${state.kernelVersion.substringBefore("-g")}",
            navigationIcon = {
                TextButton(
                    text = "返回",
                    onClick = { state.showFullLog = false },
                    minHeight = 40.dp,
                    insideMargin = PaddingValues(horizontal = 8.dp, vertical = 6.dp),
                    textStyle = MiuixTheme.textStyles.footnote1,
                )
            },
        )
        Box(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .padding(horizontal = 12.dp)
                .background(MiuixTheme.colorScheme.surfaceContainer, RoundedCornerShape(10.dp))
                .verticalScroll(logScroll)
                .padding(10.dp),
        ) {
            Text(
                text = state.logText.ifEmpty { "暂无日志" },
                fontSize = 11.sp,
                lineHeight = 16.sp,
                fontFamily = FontFamily.Monospace,
                color = if (state.logText.isEmpty())
                    MiuixTheme.colorScheme.onSurfaceVariantSummary
                else
                    MiuixTheme.colorScheme.onSurface,
            )
        }
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 6.dp),
            horizontalArrangement = Arrangement.End,
        ) {
            CompactTextButton(
                text = "导出日志",
                onClick = { activity.exportCurrentLog() },
                enabled = state.logText.isNotEmpty(),
            )
            CompactTextButton(
                text = "回到末尾",
                onClick = { scope.launch { logScroll.animateScrollTo(logScroll.maxValue) } },
            )
        }
    }
}

@Composable
private fun SuccessMetricRow(label: String, value: String) {
    val largeText = LocalDensity.current.fontScale >= 1.5f
    if (largeText) {
        Column(modifier = Modifier.fillMaxWidth()) {
            Text(
                text = label,
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Text(
                text = value,
                style = MiuixTheme.textStyles.body2,
                color = MiuixTheme.colorScheme.onSurface,
            )
        }
    } else {
        Row(modifier = Modifier.fillMaxWidth()) {
            Text(
                text = label,
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                modifier = Modifier.weight(1f),
            )
            Text(
                text = value,
                style = MiuixTheme.textStyles.body2,
                color = MiuixTheme.colorScheme.onSurface,
            )
        }
    }
}

@Composable
private fun SuccessPage(activity: MainActivity, state: UiState) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MiuixTheme.colorScheme.background)
            .statusBarsPadding()
            .navigationBarsPadding()
            .padding(horizontal = 20.dp, vertical = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(Modifier.weight(1f))
        Card(
            colors = CardDefaults.defaultColors(),
            insideMargin = PaddingValues(0.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(
                modifier = Modifier.padding(horizontal = 18.dp, vertical = 18.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    text = "提权完成",
                    fontSize = 25.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = MiuixTheme.colorScheme.onSurface,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    text = "临时 root 已生效，重启需重新提权",
                    fontSize = 11.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
                Spacer(Modifier.height(14.dp))
                HLine()
                Spacer(Modifier.height(10.dp))
                SuccessMetricRow(
                    label = "耗时",
                    value = formatElapsed(state.lastRunElapsedSec),
                )
                Spacer(Modifier.height(6.dp))
                SuccessMetricRow(
                    label = "内核后端",
                    value = if (state.chain98260) "98260-rootd（临时）" else state.ksuManagerLabel,
                )
                if (state.chain98260) {
                    Spacer(Modifier.height(6.dp))
                    Text(
                        text = "98260：rootd 仅在当前开机周期有效，重启后失效；" +
                            "清理临时文件会停止 rootd 服务；进程为内核安全保留至重启",
                        fontSize = 10.sp,
                        lineHeight = 14.sp,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                Spacer(Modifier.height(6.dp))
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
                        fontSize = 9.5.sp,
                        lineHeight = 14.sp,
                        fontFamily = FontFamily.Monospace,
                        color = MiuixTheme.colorScheme.onSurface,
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
                }
                Spacer(Modifier.height(14.dp))
                TextButton(
                    text = "导出日志",
                    onClick = { activity.exportSuccessLog() },
                    modifier = Modifier.fillMaxWidth(),
                    minHeight = 44.dp,
                )
                if (state.exportResult.isNotEmpty()) {
                    Spacer(Modifier.height(6.dp))
                    Text(
                        text = state.exportResult,
                        fontSize = 10.sp,
                        lineHeight = 14.sp,
                        color = if (state.exportOk) MiuixTheme.colorScheme.primary
                        else MiuixTheme.colorScheme.error,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                Spacer(Modifier.height(8.dp))
                Button(
                    onClick = { activity.returnHome() },
                    colors = ButtonDefaults.buttonColorsPrimary(),
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("返回主页", style = MiuixTheme.textStyles.button) }
            }
        }
        Spacer(Modifier.weight(1f))
    }
}

@Composable
private fun AboutDonationCard(onOpen: () -> Unit) {
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                text = "捐赠赞赏",
                fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold,
                color = MiuixTheme.colorScheme.primary,
            )
            Spacer(Modifier.height(6.dp))
            Text(
                text = "公益免费项目，捐赠赞赏不提供任何额外服务。",
                fontSize = 11.sp,
                lineHeight = 16.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(8.dp))
            TextButton(text = "查看赞赏码", onClick = onOpen)
        }
    }
}

@Composable
private fun DonationDialog(onDismiss: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val qrRes = R.drawable.donation_qrcode_legacy
    WindowDialog(
        show = true,
        title = "微信赞赏码",
        summary = "扫码赞赏；公益免费项目，不提供任何额外服务。",
        onDismissRequest = onDismiss,
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Image(
                painter = painterResource(qrRes),
                contentDescription = "微信赞赏二维码",
                contentScale = ContentScale.Fit,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 400.dp),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(text = "关闭", onClick = onDismiss)
                Button(
                    onClick = {
                        scope.launch {
                            val saved = withContext(Dispatchers.IO) {
                                saveDonationQrToGallery(context, qrRes, "wechat")
                            }
                            Toast.makeText(
                                context,
                                if (saved) "赞赏码已保存至 Pictures/MagicRoot"
                                else "保存失败，请重试",
                                Toast.LENGTH_SHORT,
                            ).show()
                        }
                    },
                ) {
                    Text("保存到相册", fontSize = 13.sp)
                }
            }
        }
    }
}

private fun saveDonationQrToGallery(context: Context, resId: Int, channel: String): Boolean {
    val resolver = context.contentResolver
    val values = ContentValues().apply {
        put(MediaStore.MediaColumns.DISPLAY_NAME, "MagicRoot_${channel}_donation_${System.currentTimeMillis()}.png")
        put(MediaStore.MediaColumns.MIME_TYPE, "image/png")
        put(MediaStore.MediaColumns.RELATIVE_PATH, "Pictures/MagicRoot")
        put(MediaStore.MediaColumns.IS_PENDING, 1)
    }
    val uri = resolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, values) ?: return false
    return try {
        val bitmap = BitmapFactory.decodeResource(context.resources, resId)
            ?: throw IllegalStateException("decode failed")
        val output = resolver.openOutputStream(uri)
            ?: throw IllegalStateException("open stream failed")
        output.use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
        bitmap.recycle()
        val done = ContentValues().apply { put(MediaStore.MediaColumns.IS_PENDING, 0) }
        resolver.update(uri, done, null, null)
        true
    } catch (_: Exception) {
        resolver.delete(uri, null, null)
        false
    }
}

@Composable
private fun SusfsUpdateCard(activity: MainActivity, state: UiState) {
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(5.dp),
        ) {
            Text(
                "SuSFS LKM 在线更新",
                style = MiuixTheme.textStyles.body1,
                color = MiuixTheme.colorScheme.onSurface,
            )
            Text(
                "根据当前内核从 GitHub 获取最新 guard LKM，保存到应用私有目录；提权时按 KMI 尝试加载，失败只记录，不阻断 root。",
                fontSize = 11.sp,
                lineHeight = 15.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            if (state.susfsUpdateStatus.isNotEmpty()) {
                Text(
                    state.susfsUpdateStatus,
                    fontSize = 11.sp,
                    lineHeight = 15.sp,
                    color = MiuixTheme.colorScheme.primary,
                )
            }
            CompactTextButton(
                text = if (state.susfsUpdateBusy) "更新中…" else "检查并更新 SuSFS LKM",
                onClick = { activity.updateSusfsLkm() },
                enabled = !state.susfsUpdateBusy,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Composable
private fun ThemeModeChip(
    label: String,
    selected: Boolean,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
) {
    val shape = RoundedCornerShape(13.dp)
    Box(
        modifier = modifier
            .heightIn(min = 38.dp)
            .clip(shape)
            .background(
                if (selected) MiuixTheme.colorScheme.primaryContainer
                else MiuixTheme.colorScheme.surfaceContainerHigh,
                shape,
            )
            .border(
                1.dp,
                if (selected) MiuixTheme.colorScheme.primary.copy(alpha = 0.50f)
                else Color.Transparent,
                shape,
            )
            .clickable(onClick = onClick)
            .padding(horizontal = 8.dp, vertical = 9.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = label,
            fontSize = 12.sp,
            maxLines = 1,
            color = if (selected) MiuixTheme.colorScheme.primary
            else MiuixTheme.colorScheme.onSurface,
        )
    }
}

@Composable
private fun AccentColorChip(
    key: String,
    label: String,
    color: Color,
    selected: Boolean,
    enabled: Boolean,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
) {
    val shape = RoundedCornerShape(13.dp)
    Row(
        modifier = modifier
            .heightIn(min = 38.dp)
            .clip(shape)
            .background(
                if (selected) MiuixTheme.colorScheme.primaryContainer
                else MiuixTheme.colorScheme.surfaceContainerHigh,
                shape,
            )
            .border(
                1.dp,
                if (selected) MiuixTheme.colorScheme.primary.copy(alpha = 0.55f)
                else Color.Transparent,
                shape,
            )
            .clickable(enabled = enabled, onClick = onClick)
            .padding(horizontal = 8.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Box(
            modifier = Modifier
                .size(12.dp)
                .clip(RoundedCornerShape(50))
                .background(color, RoundedCornerShape(50)),
        )
        Text(
            text = label,
            fontSize = 11.sp,
            maxLines = 1,
            color = if (selected) MiuixTheme.colorScheme.primary
            else MiuixTheme.colorScheme.onSurface,
        )
    }
}

private fun accentLabel(key: String): String = when (key) {
    "jade" -> "翡翠"
    "violet" -> "紫罗兰"
    "sunset" -> "落日"
    "rose" -> "玫瑰"
    "graphite" -> "石墨"
    else -> "Express"
}

private fun paletteLabel(key: String): String = when (key) {
    "monochrome" -> "单色"
    "neutral" -> "中性"
    "vibrant" -> "鲜艳"
    "expressive" -> "表现力"
    "fidelity" -> "忠实"
    "content" -> "内容"
    "rainbow" -> "彩虹"
    "fruit" -> "水果沙拉"
    else -> "均衡"
}

private fun hexOf(argb: Int): String = String.format("#%06X", argb and 0xFFFFFF)

private fun parseHexColor(raw: String): Int? {
    val text = raw.trim().removePrefix("#")
    if (text.length != 6 && text.length != 8) return null
    val value = text.toLongOrNull(16) ?: return null
    return if (text.length == 8) value.toInt()
    else (0xFF000000L or value).toInt()
}

private fun hsvOf(argb: Int): FloatArray {
    val out = FloatArray(3)
    android.graphics.Color.colorToHSV(argb, out)
    return out
}

@Composable
private fun CustomColorDialog(
    initial: Int,
    onDismiss: () -> Unit,
    onConfirm: (Int) -> Unit,
) {
    val initialHsv = remember(initial) { hsvOf(initial) }
    var hue by remember(initial) { mutableFloatStateOf(initialHsv[0]) }
    var saturation by remember(initial) { mutableFloatStateOf(initialHsv[1]) }
    var hex by remember(initial) { mutableStateOf(hexOf(initial)) }
    var invalid by remember(initial) { mutableStateOf(false) }
    val selected = Color(
        android.graphics.Color.HSVToColor(
            floatArrayOf(hue, saturation.coerceIn(0.05f, 1f), 0.95f)
        )
    )
    WindowDialog(
        show = true,
        title = "自定义取色",
        summary = "拖动圆盘选择色相和饱和度，或输入 HEX；只有点击“应用”才会生效。",
        onDismissRequest = onDismiss,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Canvas(
                modifier = Modifier
                    .align(Alignment.CenterHorizontally)
                    .size(210.dp)
                    .pointerInput(Unit) {
                        fun update(point: androidx.compose.ui.geometry.Offset) {
                            val center = androidx.compose.ui.geometry.Offset(
                                size.width / 2f, size.height / 2f
                            )
                            val dx = point.x - center.x
                            val dy = point.y - center.y
                            val radius = size.width / 2f
                            val distance = kotlin.math.sqrt(dx * dx + dy * dy)
                            saturation = (distance / radius).coerceIn(0f, 1f)
                            var degrees = Math.toDegrees(
                                kotlin.math.atan2(dy.toDouble(), dx.toDouble())
                            ).toFloat()
                            if (degrees < 0f) degrees += 360f
                            hue = degrees.coerceIn(0f, 359.9f)
                            hex = hexOf(
                                android.graphics.Color.HSVToColor(
                                    floatArrayOf(
                                        hue,
                                        saturation.coerceIn(0.05f, 1f),
                                        0.95f,
                                    )
                                )
                            )
                            invalid = false
                        }
                        awaitEachGesture {
                            val down = awaitFirstDown(requireUnconsumed = false)
                            update(down.position)
                            down.consume()
                            while (true) {
                                val event = awaitPointerEvent()
                                val change = event.changes.firstOrNull {
                                    it.id == down.id
                                } ?: break
                                if (!change.pressed) {
                                    change.consume()
                                    break
                                }
                                update(change.position)
                                change.consume()
                            }
                        }
                    },
            ) {
                val radius = size.minDimension / 2f
                drawCircle(
                    brush = Brush.sweepGradient(
                        listOf(
                            Color.Red, Color.Yellow, Color.Green,
                            Color.Cyan, Color.Blue, Color.Magenta, Color.Red,
                        ),
                        center = center,
                    ),
                    radius = radius,
                    center = center,
                )
                drawCircle(
                    brush = Brush.radialGradient(
                        listOf(Color.White, Color.Transparent),
                        center = center,
                        radius = radius,
                    ),
                    radius = radius,
                    center = center,
                )
                val angle = Math.toRadians(hue.toDouble())
                val thumb = androidx.compose.ui.geometry.Offset(
                    center.x + (kotlin.math.cos(angle) * radius * saturation).toFloat(),
                    center.y + (kotlin.math.sin(angle) * radius * saturation).toFloat(),
                )
                drawCircle(
                    color = Color.White.copy(alpha = 0.95f),
                    radius = 12.dp.toPx(),
                    center = thumb,
                )
                drawCircle(
                    color = selected,
                    radius = 8.5.dp.toPx(),
                    center = thumb,
                )
            }
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Box(
                    Modifier
                        .size(38.dp)
                        .clip(CircleShape)
                        .background(selected),
                )
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        "HEX 颜色值",
                        fontSize = 11.sp,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                    BasicTextField(
                        value = hex,
                        onValueChange = { raw ->
                            val filtered = raw.uppercase()
                                .filter { it.isDigit() || it in 'A'..'F' || it == '#' }
                                .take(9)
                            hex = if (filtered.startsWith("#")) filtered else "#$filtered"
                            val parsed = parseHexColor(hex)
                            invalid = parsed == null
                            if (parsed != null) {
                                val hsv = hsvOf(parsed)
                                hue = hsv[0]
                                saturation = hsv[1].coerceIn(0.05f, 1f)
                            }
                        },
                        singleLine = true,
                        textStyle = TextStyle(
                            color = MiuixTheme.colorScheme.onSurface,
                            fontSize = 15.sp,
                            fontFamily = FontFamily.Monospace,
                        ),
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 3.dp)
                            .clip(RoundedCornerShape(10.dp))
                            .background(MiuixTheme.colorScheme.surfaceContainerHigh)
                            .padding(horizontal = 10.dp, vertical = 9.dp),
                    )
                }
            }
            if (invalid) {
                Text(
                    "请输入 #RRGGBB 或 #AARRGGBB",
                    fontSize = 10.sp,
                    color = MiuixTheme.colorScheme.error,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(text = "取消", onClick = onDismiss)
                Button(
                    onClick = {
                        val parsed = parseHexColor(hex) ?: selected.toArgb()
                        onConfirm(parsed)
                        onDismiss()
                    },
                    modifier = Modifier.weight(1f),
                    enabled = !invalid,
                ) {
                    Text("应用颜色", style = MiuixTheme.textStyles.button)
                }
            }
        }
    }
}

@Composable
private fun AppearanceCard(state: UiState) {
    var showCustomColor by remember { mutableStateOf(false) }
    val currentAccent = when (state.accentColor) {
        "jade" -> 0xFF18A57A.toInt()
        "violet" -> 0xFF8B5CF6.toInt()
        "sunset" -> 0xFFFF7A45.toInt()
        "rose" -> 0xFFE5487A.toInt()
        "graphite" -> 0xFF6B7280.toInt()
        "custom" -> state.customAccent
        else -> 0xFF3D7EFF.toInt()
    }
    val variants = if (state.colorSpec == "2025") {
        listOf(
            "neutral" to "中性",
            "tonal" to "均衡",
            "vibrant" to "鲜艳",
            "expressive" to "表现力",
        )
    } else {
        listOf(
            "monochrome" to "单色",
            "neutral" to "中性",
            "tonal" to "均衡",
            "vibrant" to "鲜艳",
            "expressive" to "表现力",
            "fidelity" to "忠实",
            "content" to "内容",
            "rainbow" to "彩虹",
            "fruit" to "水果沙拉",
        )
    }
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text("外观", style = MiuixTheme.textStyles.title4)
            Text(
                "默认主题：Express · Tonal Spot · M3 2021 · Liquid Glass 底栏。",
                fontSize = 11.sp,
                lineHeight = 15.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                ThemeModeChip(
                    label = "跟随系统",
                    selected = state.themeMode == "system",
                    modifier = Modifier.weight(1f),
                ) { state.updateThemeMode("system") }
                ThemeModeChip(
                    label = "浅色",
                    selected = state.themeMode == "light",
                    modifier = Modifier.weight(1f),
                ) { state.updateThemeMode("light") }
                ThemeModeChip(
                    label = "深色",
                    selected = state.themeMode == "dark",
                    modifier = Modifier.weight(1f),
                ) { state.updateThemeMode("dark") }
            }
            CompactToggle(
                title = "Material You 动态取色",
                subtitle = if (state.dynamicColor) {
                    "已启用系统 Monet 调色板；优先使用壁纸取色"
                } else {
                    "关闭时使用 ${accentLabel(state.accentColor)} / ${paletteLabel(state.paletteStyle)}"
                },
                checked = state.dynamicColor,
                enabled = true,
                onCheckedChange = { state.updateDynamicColor(it) },
            )
            Text(
                "Material 规范",
                fontSize = 11.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                ThemeModeChip(
                    label = "M3 2021 · 9 Variant",
                    selected = state.colorSpec == "2021",
                    modifier = Modifier.weight(1.35f),
                ) { state.updateColorSpec("2021") }
                ThemeModeChip(
                    label = "M3 2025 · 4 Variant",
                    selected = state.colorSpec == "2025",
                    modifier = Modifier.weight(1.15f),
                ) { state.updateColorSpec("2025") }
            }
            if (state.dynamicColor) {
                Text(
                    "Monet 已接管调色板；当前只允许切换 Material 规范。" +
                        "关闭动态取色后会恢复之前保存的 ${accentLabel(state.accentColor)} / ${paletteLabel(state.paletteStyle)}。",
                    fontSize = 10.sp,
                    lineHeight = 14.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
            } else {
                Text(
                    "调色变体（默认 Tonal Spot）",
                    fontSize = 11.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
                variants.chunked(3).forEach { row ->
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        row.forEach { (key, label) ->
                            ThemeModeChip(
                                label = label,
                                selected = state.paletteStyle == key,
                                modifier = Modifier.weight(1f),
                            ) { state.updatePaletteStyle(key) }
                        }
                        repeat(3 - row.size) { Spacer(Modifier.weight(1f)) }
                    }
                }
                if (state.colorSpec == "2025") {
                    Text(
                        "2025 的 Vibrant / Expressive 彩度更高；暗色下建议 Tonal Spot 或 Neutral。",
                        fontSize = 10.sp,
                        lineHeight = 14.sp,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                }
                Text(
                    "取色方案",
                    fontSize = 11.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    AccentColorChip(
                        key = "express", label = "Express", color = Color(0xFF3D7EFF),
                        selected = state.accentColor == "express",
                        enabled = true, modifier = Modifier.weight(1f),
                    ) { state.updateAccentColor("express") }
                    AccentColorChip(
                        key = "jade", label = "翡翠", color = Color(0xFF18A57A),
                        selected = state.accentColor == "jade",
                        enabled = true, modifier = Modifier.weight(1f),
                    ) { state.updateAccentColor("jade") }
                    AccentColorChip(
                        key = "violet", label = "紫罗兰", color = Color(0xFF8B5CF6),
                        selected = state.accentColor == "violet",
                        enabled = true, modifier = Modifier.weight(1f),
                    ) { state.updateAccentColor("violet") }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    AccentColorChip(
                        key = "sunset", label = "落日", color = Color(0xFFFF7A45),
                        selected = state.accentColor == "sunset",
                        enabled = true, modifier = Modifier.weight(1f),
                    ) { state.updateAccentColor("sunset") }
                    AccentColorChip(
                        key = "rose", label = "玫瑰", color = Color(0xFFE5487A),
                        selected = state.accentColor == "rose",
                        enabled = true, modifier = Modifier.weight(1f),
                    ) { state.updateAccentColor("rose") }
                    AccentColorChip(
                        key = "graphite", label = "石墨", color = Color(0xFF6B7280),
                        selected = state.accentColor == "graphite",
                        enabled = true, modifier = Modifier.weight(1f),
                    ) { state.updateAccentColor("graphite") }
                }
                TextButton(
                    text = "自定义颜色…",
                    onClick = { showCustomColor = true },
                    modifier = Modifier.fillMaxWidth(),
                    minHeight = 40.dp,
                )
                if (state.accentColor == "custom") {
                    Text(
                        "当前自定义：${hexOf(currentAccent)}",
                        fontSize = 10.sp,
                        color = MiuixTheme.colorScheme.primary,
                    )
                }
            }
            CompactToggle(
                title = "Liquid Glass 底栏",
                subtitle = if (state.glassBottomBar) {
                    "浮动胶囊、折射与横向滑动；关闭后切回旧版 M3 底栏"
                } else {
                    "旧版 Material Design 3 全宽底栏（无玻璃）"
                },
                checked = state.glassBottomBar,
                enabled = true,
                onCheckedChange = { state.updateGlassBottomBar(it) },
            )
            TextButton(
                text = "重置为默认主题",
                onClick = { state.resetAppearance() },
                modifier = Modifier.fillMaxWidth(),
                minHeight = 40.dp,
            )
            Text(
                when {
                    state.dynamicColor -> "当前：Monet 系统取色 · ${paletteLabel(state.paletteStyle)}"
                    else -> "当前：${accentLabel(state.accentColor)} · ${paletteLabel(state.paletteStyle)} · M3 ${state.colorSpec}"
                },
                fontSize = 10.sp,
                color = MiuixTheme.colorScheme.primary,
            )
        }
    }
    if (showCustomColor) {
        CustomColorDialog(
            initial = currentAccent,
            onDismiss = { showCustomColor = false },
            onConfirm = { state.updateCustomAccent(it) },
        )
    }
}

@Composable
private fun AboutPage(activity: MainActivity, state: UiState) {
    val uriHandler = LocalUriHandler.current
    val aboutContext = LocalContext.current
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MiuixTheme.colorScheme.background),
    ) {
        Column(
            modifier = Modifier
                .weight(1f)
                .statusBarsPadding()
                .padding(horizontal = 16.dp, vertical = 10.dp)
                .padding(bottom = 16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Card(
                colors = CardDefaults.defaultColors(),
                insideMargin = PaddingValues(0.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp)) {
                    Text(
                        text = "MagicRoot",
                        fontSize = 32.sp,
                        lineHeight = 38.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = (-0.4).sp,
                        color = MiuixTheme.colorScheme.onSurface,
                    )
                    Text(
                        text = "零特权提权链路",
                        fontSize = 13.sp,
                        lineHeight = 18.sp,
                        letterSpacing = 0.3.sp,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                    Spacer(Modifier.height(8.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = "版本 1.0.6",
                            fontSize = 11.sp,
                            lineHeight = 15.sp,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                            modifier = Modifier
                                .weight(1f)
                                .clickable {
                                    if (state.registerVersionTap()) {
                                        Toast.makeText(
                                            aboutContext,
                                            "NEKO // 98260 已解锁",
                                            Toast.LENGTH_SHORT,
                                        ).show()
                                    }
                                },
                        )
                        TextButton(
                            text = "作者主页",
                            onClick = {
                                uriHandler.openUri("https://www.coolapk.com/u/34661335")
                            },
                            minHeight = 34.dp,
                        )
                    }
                    Text(
                        text = "作者：酷安@青木信史",
                        fontSize = 12.sp,
                        lineHeight = 17.sp,
                        color = MiuixTheme.colorScheme.onSurface,
                    )
                }
            }
            if (state.eggUnlocked) {
                Card(
                    colors = CardDefaults.defaultColors(),
                    insideMargin = PaddingValues(0.dp),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        Text(
                            "NEKO // 98260",
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold,
                            color = MiuixTheme.colorScheme.primary,
                        )
                        Text(
                            "七个版本号之后，猫在计时器里留了一盏灯。",
                            fontSize = 12.sp,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                        Text(
                            "保持好奇，保持可恢复。 — MagicRoot",
                            fontSize = 11.sp,
                            color = MiuixTheme.colorScheme.onSurface,
                        )
                    }
                }
            }
            AppearanceCard(state)
            AboutSection(
                "支持内核版本（同一 uname -r 通用，不区分机型）",
                listOf(
                    "6.18.21 · g928d1bb4f1d7 · 98260 · 静态适配",
                    "6.18.21 · ge186062ea75f · 98260 · 静态适配",
                    "6.18.21 · gfee2325de189 · 98260 H1C 117 · 静态适配",
                    "6.12.58 · g3a7ac1674240 · 98260 + 64560 · 已实机",
                    "6.12.58 · g459a4285ccf8 · 98260 · 已实机",
                    "6.12.58 · g142ddad31e60 · 98260 + 64560 · 静态适配",
                    "6.12.38 · g7ae8ec909e03 · 98260 · 已实机",
                    "6.12.38 · gfde7767f6ef6 · 98260 · 已实机",
                    "6.12.23 · g45ea5e4bce8a · 98260 · 已实机",
                    "6.12.23 · gcd85666d7884 · 98260 · 静态适配",
                    "6.6.118 · g554929766a0d · 98260 · 已实机",
                    "6.6.118 · gf17133276a57 · 98260 · 已实机",
                    "6.6.118 · ga812a1946391 · 98260 · 静态适配",
                    "6.6.118 · g893e848657cc · 98260 · 静态适配",
                    "6.6.58 · g6484937db664 · 98260 · 静态适配",
                    "6.6.89 · g082e5a98dac1 · 98260 · 静态适配",
                    "6.1.157 · g2646292297b1 · 98260 · 已实机",
                    "6.1.157 · gaaa383620ebf · 98260 · 静态适配",
                    "6.1.157 · g3306a328b7be · 98260 · 静态适配",
                    "6.1.157 · g77f76e323a02 · 98260 · 静态适配",
                    "6.1.157 · g7d3922fade43 · 98260 · 静态适配",
                    "6.1.157 · g84ffa64b710b · 98260 · 静态适配",
                    "6.1.157 · g8d63307071ad · 98260 · 静态适配",
                    "6.1.128 · g40b1fd119d9b · 98260 · 静态适配",
                    "6.1.128 · g8a4968670f1c · 98260 · 静态适配",
                    "6.1.128 · g2e1f0741dafb · 98260 · 静态适配",
                    "6.1.99 · g54d40b4fb287 · 98260 · 静态适配",
                    "6.1.99 · g5859fbdbad8c · 98260 · 静态适配",
                    "6.1.99 · gce84935796c9 · 98260 · 静态适配",
                    "6.1.99 · ge9da27488f45 · 98260 · 静态适配",
                ),
            )
            AboutSection(
                "98260 适配致谢",
                listOf(
                    "GitHub / 酷安 Higanoneko",
                ),
            )
            AboutSection(
                "fake / real 双分支与 late-load",
                listOf(
                    "fake-cred：rootd 交付后，直接由当前管理器 ksud late-load 配套 LKM；不经过 ko_patch",
                    "real-cred：独立 cap 验证后 direct-finit，再由同一管理器 ksud late-load 完成用户态闭环",
                    "两条分支均不修改 packages.list；管理器 ksud 与 LKM 必须来自同一 APK",
                ),
            )
            AboutSection(
                "使用范围与风险",
                listOf(
                    "仅供自有、已授权调试设备的安全研究使用",
                    "提权过程可能触发内核异常、设备重启或数据丢失；请先备份并确保设备可恢复",
                    "不保证成功率，不适用于生产环境或他人设备",
                ),
            )
            AboutLinkSection(
                title = "项目与参考",
                links = listOf(
                    "[源码] 98260 初始 plant 与 rootd/su · xiaomi9pmroot"
                        to "https://github.com/EAEdward/xiaomi9pmroot",
                    "[源码] 98260 real-cred 原语 · woshigenm"
                        to "https://github.com/woshigenm/CVE-2026-98260",
                    "[源码] 98260 rootd/su 最早公开共享 · popsicle"
                        to "https://github.com/quyicheng03-boop/CVE-2026-98260-popsicle-android",
                    "[源码] 6.18 H1C / boot 解析 / 64560 · HOneClick"
                        to "https://github.com/superboyyy/HOneClick",
                    "[源码] 64560 零写原语 · CVE-2026-64560-public"
                        to "https://github.com/Feng1586/CVE-2026-64560-public",
                    "[随包分发·未用源码] KernelSU · LKM 模板"
                        to "https://github.com/tiann/KernelSU",
                    "[随包分发·未用源码] SuSFS LKM · susfs4ksu-lkm"
                        to "https://github.com/inforcqb/susfs4ksu-lkm",
                    "[仅参考·未用源码] 98260 流程 · OnePlus16-Jailbreak"
                        to "https://github.com/Yunnijian/OnePlus16-Jailbreak",
                    "[仅参考·未用源码] 98260 6.12.69 · YuKongA"
                        to "https://github.com/YuKongA/CVE-2026-98260",
                    "[仅参考·未用源码] 日志验收 · OneKey / onekeyjb"
                        to "https://github.com/xingranya/onekeyjb",
                    "[仅参考·未用源码] 64560 清理 · No-World/rootkit"
                        to "https://github.com/No-World/rootkit",
                    "[仅参考·未用源码] su entry · PMX110"
                        to "https://github.com/TKgbUssr/PMX110-6.18.21-exploit",
                ),
                footer = "本项目自研代码：AGPL-3.0（1.0.6 起；1.0.5 及更早为 MIT）；第三方源码与随包预编译产物各自沿用原协议（MIT / Apache-2.0 / GPL-2.0 / GPL-3.0）",
                onOpen = { uriHandler.openUri(it) },
            )
            AboutDonationCard(onOpen = { state.showDonation = true })
            AboutSection(
                "本项目与源码复用许可（实际纳入代码）",
                listOf(
                    "MagicRoot 自研部分（应用 UI/控制器/部署脚本/适配修改）：GNU AGPL-3.0（Copyright (c) 2026 MagicRoot contributors，1.0.6 起；1.0.5 及更早为 MIT），不重新授权第三方二进制或 GPL 模块；通过网络提供修改版服务时须按 AGPL 第 13 条提供对应源码",
                    "许可兼容性：AGPL-3.0 与 MIT / Apache-2.0 / GPL-3.0 兼容，与 GPL-2.0-only 不兼容；随包 KernelSU 系 GPL-2.0 预编译 LKM 按独立作品分发，不在本项目重授权范围内",
                    "EAEdward/xiaomi9pmroot（原 yt-root-98260，MIT，Copyright (c) 2026 yt-root-98260 contributors）：使用并二次修改 6.12/6.6 初始 uaf_plant 与 rootd/su 基础",
                    "woshigenm/CVE-2026-98260（MIT，Copyright (c) 2026 woshigenm）：移植并合入 real-cred 最终写入三原语与回收状态逻辑",
                    "quyicheng03-boop/CVE-2026-98260-popsicle-android（MIT，Copyright (c) 2026 quyicheng03-boop）：共享 pc98260_su/rootd 最早公开来源；未使用其 plant 源码",
                    "superboyyy/HOneClick（根 LICENSE 为 MIT 带范围尾注，Copyright (c) 2026 superboyyy；API 标 NOASSERTION）：移植 KernelProfileGenerator、6.18 H1C 与 64560 源码（其 98260 rootd 溯源至 sganggs/popsicle）",
                    "Feng1586/CVE-2026-64560-public（根 LICENSE 为 MIT 带范围尾注，Copyright (c) 2026 GhostLock/CVE-2026-64560 research contributors）：64560 t64560_v36/v42 零写原语基础",
                    "honor_ubl 3.1.1 aph136g142（MIT）：kaslr_slide_aph136g142 与 G142 目标常量",
                    "Miuix / Compose Multiplatform / AndroidX / Shizuku API（XiaoTong6666 fork）/ AndroidLiquidGlass：Apache-2.0",
                ),
            )
            AboutSection(
                "随包分发预编译产物（未使用上游源码构建）",
                listOf(
                    "KernelSU / KernelSU-Next / BakaSU（GPL-2.0）、SukiSU Ultra（GPL-3.0）、FinaSU（遵循上游）：仅随 APK 打包预编译 .ko 模板与 6.1/6.18 历史回退 ksud；通用路径运行时从已安装管理器提取 ksud，未使用管理器源码编译",
                    "SuSFS（inforcqb/susfs4ksu-lkm，遵循上游）：仅随包分发预编译 susfs_insmod 与 susfs_guard_lkm-*.ko，未使用源码编译",
                    "6.1.x CGA 基线（ksm-*-base.ko）与 64560 历史发布二进制：发布包沿用已验证预编译产物随包分发，对应审计源码保存在 binary-sources/",
                ),
            )
            AboutSection(
                "仅作技术参考（未复用源码、未随包分发）",
                listOf(
                    "YuKongA/CVE-2026-98260（MIT）、AzirX1337（MIT）、OnePlus16-Jailbreak（GPL-3.0；早期快照 MIT）、onekeyjb（GPL-3.0）、No-World/rootkit（MIT）、PMX110",
                    "LSPosed / Zygisk Next：不打包内置 APK 或模块，仅设备端脚本热修复",
                    "完整许可证文本见源码包 LICENSE，版权声明与文件级边界见 NOTICE.md、THIRD_PARTY_NOTICES.md 与 LICENSES/",
                ),
            )
            AboutSection(
                "清理说明",
                listOf(
                    "98260 rootd 采用安全停止：停止服务并删除 socket，持有 timer-UAF 僵尸的父进程保留至重启",
                    "清理按钮只移除本工具运行时产生的临时文件，不卸载或修改系统中已有组件",
                ),
            )
            AboutSection(
                "免责声明",
                listOf(
                    "使用前请确认设备归属和当地法律；本工具不提供任何担保",
                ),
            )
            // The glass bottom bar floats over the page; reserve its height so
            // the final section can be scrolled fully into view.
            Spacer(Modifier.height(112.dp))
        }
    }
}

@Composable
private fun AboutLinkSection(
    title: String,
    links: List<Pair<String, String>>,
    footer: String,
    onOpen: (String) -> Unit,
) {
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            SectionTitle(title)
            links.forEach { (label, url) ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .clickable { onOpen(url) }
                        .padding(vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        label,
                        fontSize = 12.sp,
                        lineHeight = 18.sp,
                        color = MiuixTheme.colorScheme.onSurface,
                        modifier = Modifier.weight(1f),
                    )
                    Text(
                        "↗",
                        fontSize = 14.sp,
                        color = MiuixTheme.colorScheme.primary,
                    )
                }
            }
            Spacer(Modifier.height(4.dp))
            Text(
                footer,
                fontSize = 10.sp,
                lineHeight = 15.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
        }
    }
}

@Composable
private fun AboutSection(title: String, lines: List<String>) {
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
            SectionTitle(title)
            lines.forEach { line ->
                Text(
                    text = line,
                    fontSize = 11.sp,
                    lineHeight = 18.sp,
                    letterSpacing = 0.1.sp,
                    color = MiuixTheme.colorScheme.onSurface,
                )
                Spacer(Modifier.height(3.dp))
            }
        }
    }
}

@Composable
private fun HeroCard(state: UiState) {
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(18.dp)) {
            Text(
                text = "MagicRoot",
                fontSize = 13.sp,
                fontWeight = FontWeight.Medium,
                color = MiuixTheme.colorScheme.primary,
            )
            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                StatusPill(
                    text = when {
                        state.running -> "运行中"
                        state.busy -> "处理中"
                        else -> "就绪"
                    },
                    color = when {
                        state.running -> MiuixTheme.colorScheme.primaryContainer
                        state.busy -> MiuixTheme.colorScheme.secondaryContainer
                        else -> MiuixTheme.colorScheme.tertiaryContainer
                    },
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    text = state.status,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    fontSize = 12.sp,
                )
            }
            Spacer(Modifier.height(12.dp))
            Text(
                text = "零特权提权链路",
                fontSize = 26.sp,
                fontWeight = FontWeight.SemiBold,
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = "CVE-2026-64560 · posix-cpu-timers · ${state.ksuManagerLabel} LKM",
                fontSize = 12.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(6.dp))
            Text(
                text = "内核 ${state.kernelVersion}",
                fontSize = 10.5.sp,
                lineHeight = 15.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(14.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatusPill(
                    if (state.bakasuBackend) "BakaSU 内核" else "官方 KSU 内核",
                    MiuixTheme.colorScheme.primaryContainer,
                )
                StatusPill("保守参数", MiuixTheme.colorScheme.primaryContainer)
                StatusPill("Victim 档位", MiuixTheme.colorScheme.secondaryContainer)
            }
        }
    }
}

@Composable
private fun FeedbackBanner(state: UiState, modifier: Modifier = Modifier) {
    if (state.feedbackTitle.isEmpty()) return
    val title = state.feedbackTitle
    // Finished (success/error) feedback is transient; keep the inline banner
    // for a few seconds so it never lingers as a fake popup.
    LaunchedEffect(title, state.feedbackTone, state.busy, state.running) {
        if (!state.busy && !state.running) {
            delay(4500)
            if (!state.busy && !state.running && state.feedbackTitle == title) {
                state.clearFeedback()
            }
        }
    }
    val tone = when {
        state.busy || state.running -> statusTone("info")
        state.feedbackTone == 2 -> statusTone("error")
        state.feedbackTone == 1 -> statusTone("success")
        else -> statusTone("info")
    }
    Surface(
        color = tone.bg,
        shape = RoundedCornerShape(14.dp),
        modifier = modifier,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 11.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (state.busy || state.running) {
                Box(
                    modifier = Modifier.size(20.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    // Miuix's indicator overrides its own size internally;
                    // pass the diameter parameter instead of a modifier.
                    CircularProgressIndicator(
                        size = 16.dp,
                        strokeWidth = 2.dp,
                    )
                }
            } else {
                Box(
                    modifier = Modifier
                        .size(20.dp)
                        .background(tone.fg, RoundedCornerShape(50)),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = when (state.feedbackTone) {
                            2 -> "!"
                            1 -> "✓"
                            else -> "i"
                        },
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = tone.bg,
                    )
                }
            }
            Spacer(Modifier.width(10.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = state.feedbackTitle,
                    style = MiuixTheme.textStyles.body2,
                    color = tone.fg,
                )
                if (state.feedbackDetail.isNotEmpty()) {
                    Text(
                        text = state.feedbackDetail,
                        style = MiuixTheme.textStyles.footnote2,
                        color = tone.fg.copy(alpha = 0.78f),
                    )
                }
            }
        }
    }
}

@Composable
private fun PrepareCard(activity: MainActivity, state: UiState) {
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            SectionTitle("准备")
            Text(
                text = "通过 Shizuku 获得 shell，再部署运行资产",
                fontSize = 12.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                modifier = Modifier.padding(bottom = 10.dp),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Button(
                    onClick = { activity.doGrant() },
                    enabled = !state.busy,
                    modifier = Modifier.weight(1f),
                ) { Text("授权 Shell") }
                Button(
                    onClick = { activity.doStage() },
                    enabled = !state.busy,
                    modifier = Modifier.weight(1f),
                ) { Text("部署资产") }
            }
        }
    }
}

@Composable
private fun RunCard(activity: MainActivity, state: UiState) {
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            SectionTitle("执行")
            Text(
                text = "同步完成 KASLR、SELinux、cred 两阶段写与模块加载",
                fontSize = 12.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                modifier = Modifier.padding(bottom = 10.dp),
            )
            Button(
                onClick = { activity.startRun() },
                enabled = !state.busy && !state.running,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    when {
                        state.running -> "提权执行中…"
                        state.busy -> "处理中…"
                        else -> "开始提权"
                    },
                )
            }
            Spacer(Modifier.height(8.dp))
            TextButton(
                text = "清理临时文件",
                onClick = { activity.doClean() },
                enabled = !state.busy,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Composable
private fun ParameterCard(state: UiState) {
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            SectionTitle("参数")
            Text(
                text = "Victim 档位",
                fontSize = 12.sp,
                fontWeight = FontWeight.Medium,
                color = MiuixTheme.colorScheme.onSurface,
                modifier = Modifier.padding(top = 2.dp, bottom = 8.dp),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = { state.cyclePerm() },
                    enabled = !state.busy,
                    modifier = Modifier.weight(1f),
                ) { Text("SE ${state.victimPerm}", maxLines = 1, fontSize = 12.sp) }
                Button(
                    onClick = { state.cycleFsuid() },
                    enabled = !state.busy,
                    modifier = Modifier.weight(1f),
                ) { Text("fsuid ${state.victimFsuid}", maxLines = 1, fontSize = 12.sp) }
                Button(
                    onClick = { state.cycleCred() },
                    enabled = !state.busy,
                    modifier = Modifier.weight(1f),
                ) { Text("cred ${state.victimCred}", maxLines = 1, fontSize = 12.sp) }
            }
            Spacer(Modifier.height(8.dp))
            HLine()
            HLine()
        }
    }
}

@Composable
private fun CompactToggle(
    title: String,
    subtitle: String,
    checked: Boolean,
    enabled: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    SwitchPreference(
        checked = checked,
        onCheckedChange = onCheckedChange,
        title = title,
        summary = subtitle,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
private fun ToggleRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    enabled: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    SwitchPreference(
        checked = checked,
        onCheckedChange = onCheckedChange,
        title = title,
        summary = subtitle,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
private fun LogCard(state: UiState) {
    Card(
        colors = CardDefaults.defaultColors(),
        insideMargin = PaddingValues(0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                TextButton(
                    text = "清空显示",
                    onClick = { state.replaceLog("") },
                    enabled = state.logText.isNotEmpty(),
                )
            }
            val logScroll = rememberScrollState()
            LaunchedEffect(state.logText) {
                logScroll.animateScrollTo(logScroll.maxValue)
            }
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 120.dp, max = 320.dp)
                    .background(
                        MiuixTheme.colorScheme.surfaceContainerHigh,
                        RoundedCornerShape(10.dp),
                    )
                    .verticalScroll(logScroll)
                    .padding(10.dp),
            ) {
                Text(
                    text = state.logText.ifEmpty { "暂无日志。部署资产后开始提权" },
                    fontSize = 10.5.sp,
                    lineHeight = 16.sp,
                    fontFamily = FontFamily.Monospace,
                    color = if (state.logText.isEmpty())
                        MiuixTheme.colorScheme.onSurfaceVariantSummary
                    else
                        MiuixTheme.colorScheme.onSurface,
                )
            }
        }
    }
}

private data class StatusToneColors(val bg: Color, val fg: Color)

@Composable
private fun statusTone(tone: String): StatusToneColors {
    val scheme = MiuixTheme.colorScheme
    return when (tone) {
        "success" -> StatusToneColors(
            scheme.primaryContainer,
            scheme.onPrimaryContainer,
        )
        "info" -> StatusToneColors(
            scheme.secondaryContainer,
            scheme.onSecondaryContainer,
        )
        "warn" -> StatusToneColors(
            scheme.tertiaryContainer,
            scheme.onTertiaryContainer,
        )
        "error" -> StatusToneColors(
            scheme.errorContainer,
            scheme.onErrorContainer,
        )
        else -> StatusToneColors(
            scheme.surfaceContainerHigh,
            scheme.onSurfaceVariantSummary,
        )
    }
}

@Composable
private fun StatusPill(
    text: String,
    color: Color,
    contentColor: Color = MiuixTheme.colorScheme.onSurface,
) {
    Surface(
        color = color,
        shape = RoundedCornerShape(50),
    ) {
        Text(
            text = text,
            fontSize = 11.sp,
            color = contentColor,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
        )
    }
}

@Composable
private fun SectionTitle(text: String, modifier: Modifier = Modifier) {
    SmallTitle(text = text, modifier = modifier)
}

@Composable
private fun HLine() {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(1.dp)
            .background(MiuixTheme.colorScheme.outline.copy(alpha = 0.25f)),
    )
}









