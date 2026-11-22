#!/usr/bin/env python3
"""Static regression gate for the 98260 timer-UAF lifetime.

The real fatal path needs the vulnerable kernel and must not be triggered by an
unattended test.  This gate locks down the userspace lifetime invariants around
that path; it is not a substitute for an explicitly approved on-device test.
"""
from __future__ import annotations

import re
import subprocess
import tempfile
import unittest
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "binary-sources/98260-6.12/uaf_plant_61258.c"
HOTFIX = ROOT / "main/app/assets/lsposed-hotfix.sh"
PATCHER_PATH = ROOT / "tools/patch_sukisu_lateload.py"
SPEC = importlib.util.spec_from_file_location("sukisu_lateload_patch", PATCHER_PATH)
PATCHER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(PATCHER)


def function_body(source: str, name: str) -> str:
    match = re.search(rf"\b{re.escape(name)}\s*\([^;]*?\)\s*\{{", source, re.S)
    if not match:
        raise AssertionError(f"function not found: {name}")
    opening = source.find("{", match.start())
    depth = 0
    for index in range(opening, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:index]
    raise AssertionError(f"unterminated function: {name}")


class UafLifetimeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.main = function_body(cls.source, "main")
        cls.one_uaf = function_body(cls.source, "one_uaf")
        cls.reclaim_stream = function_body(cls.source, "reclaim_stream")
        cls.find_page_alloc = function_body(cls.source, "find_page_alloc")
        cls.hotfix = HOTFIX.read_text(encoding="utf-8")
        cls.runner = (ROOT / "main/app/assets/98260/run98260.sh").read_text(encoding="utf-8")
        cls.root_stage = (ROOT / "main/app/assets/root_stage.sh").read_text(encoding="utf-8")
        cls.controller = (ROOT / "main/compose-app/app/src/main/java/com/aoki/magicroot/MainActivity.java").read_text(encoding="utf-8")

    def test_parent_is_subreaper_before_first_uaf_child(self) -> None:
        self.assertIn("#include <sys/prctl.h>", self.source)
        self.assertRegex(
            self.main,
            r"prctl\s*\(\s*PR_SET_CHILD_SUBREAPER\s*,\s*1\s*,\s*0\s*,\s*0\s*,\s*0\s*\)",
            "orphaned UAF helpers must reparent to the parked exploit, not init",
        )
        self.assertLess(self.main.index("PR_SET_CHILD_SUBREAPER"), self.main.index("leak_real_cred()"))

    def test_parent_ignores_nonfatal_session_teardown_signals(self) -> None:
        setup = self.main[: self.main.index("leak_real_cred()")]
        for sig in ("SIGHUP", "SIGTERM", "SIGINT", "SIGQUIT"):
            self.assertRegex(setup, rf"signal\s*\(\s*{sig}\s*,\s*SIG_IGN\s*\)")

    def test_stream_hit_requires_current_process_allocation(self) -> None:
        self.assertIn("trace_task_is_self", self.source)
        self.assertIn("getpid()", function_body(self.source, "trace_task_is_self"))
        self.assertIn("trace_task_is_self(t->line)", self.find_page_alloc)
        self.assertLess(
            self.find_page_alloc.index("trace_task_is_self(t->line)"),
            self.find_page_alloc.index("return 1"),
        )

    def test_trace_scan_is_per_cpu_newest_first(self) -> None:
        # Regression for FAIL=80 on 6.12.58 g142: the old shared 4 MiB forward
        # budget starved cpu>=1 dumps under load, so alloc events on the free
        # cpu were never seen.  The scan must be newest-first per cpu with a
        # per-cpu budget, and find_page_alloc must prefer the free cpu.
        self.assertIn("struct trace_tail", self.source)
        self.assertIn("trace_tail_open", self.source)
        self.assertIn("trace_tail_next", self.source)
        # find_page_free is the dispatcher (raw first, text fallback); the
        # per-cpu newest-first scan lives in find_page_free_text.
        free_fn = function_body(self.source, "find_page_free_text")
        alloc_fn = self.find_page_alloc
        self.assertIn("trace_tail_next(t)", free_fn)
        self.assertIn("trace_tail_next(t)", alloc_fn)
        # Per-cpu budget, not one shared counter across all cpus: each cpu
        # iteration declares its own budget inside the loop.
        self.assertIn("budget = TRACE_FREE_TAIL_BUDGET", free_fn)
        self.assertIn("budget = TRACE_SCAN_BUDGET", alloc_fn)
        self.assertEqual(alloc_fn.count("budget = TRACE_SCAN_BUDGET"), 1)
        # prefer_cpu ordering: free cpu is scanned first.
        self.assertIn("prefer_cpu", alloc_fn)
        self.assertLess(alloc_fn.index("prefer_cpu"), alloc_fn.index("trace_tail_open"))
        # Call sites pass the free cpu so the pinned cpu is scanned first.
        # The 4 KiB half retry needs a single-page matcher; the 8 KiB path
        # below still requires an order>=1 allocation covering both halves.
        self.assertIn("find_page_alloc_page(free_pfn, free_cpu)", self.source)
        # The stale node is on one 4 KiB half; checking only the 8 KiB base was
        # a false-positive regression and must not return with the scan port.
        self.assertIn("find_page_alloc(node_pfn, free_cpu)", self.source)
        self.assertNotIn("find_page_alloc(base, free_cpu)", self.source)
        # Miss diagnostics distinguish "never allocated" from "task mismatch".
        self.assertIn("g_alloc_cover", self.source)
        self.assertIn("cover=%lu", self.source)

    def test_post_churn_miss_wait_is_short_and_bounded(self) -> None:
        # 22:27 run: four attempts whose full timer churn found no free then
        # waited the UI's 25 s cap each, accounting for ~100 s of a 169 s fail.
        # Active churn exhaustion leaves only a short in-flight-free tail; the
        # configured cap is still honoured as an upper bound.
        body = self.reclaim_stream
        self.assertIn("PC98260_POST_CHURN_WAIT_MS", body)
        # 2026-11-14 00:06 g142: a late free (churn rounds 2-5 on later
        # attempts) arrived after the old 1 s tail and left an unproven
        # victim; 5 s keeps that free inside the wait.
        self.assertIn("5000, 0, 60000", body)
        self.assertIn("if (tail_ms < wait_ms)", body)
        self.assertIn(">= wait_ms", body)
        self.assertIn("configured %ld ms", body)
        self.assertNotIn(">= cap_ms", body)

    def test_stream_writes_require_free_and_use_bounded_4096_budget(self) -> None:
        # OnekeyJB/Shark success spec: RECLAIM_FREED=1 before RECLAIM_WRITES=4096,
        # with hit termination.  Never spray on a free-detection miss; when free
        # is proven, use the larger bounded budget instead of stopping at 480.
        body = self.reclaim_stream
        skip = body.index("if (!freed)")
        spray = body.index("write_budget =", skip)
        self.assertIn("skip writes: no proven page free", body[skip:spray])
        self.assertIn("victim_eval_miss(v)", body[skip:spray])
        self.assertIn('PC98260_STREAM_WRITE_BUDGET", 4096, 80, 16384', body)
        self.assertIn("round < spray_rounds && !hit", body)
        self.assertIn("find_page_alloc(node_pfn, free_cpu)", body)

    def test_successful_stream_hit_retains_socket_pages(self) -> None:
        self.assertRegex(self.reclaim_stream, r"if\s*\(!hit\)\s*close_stream\s*\(\s*\)")
        self.assertNotRegex(self.reclaim_stream, r"if\s*\(hit\)\s*close_stream\s*\(\s*\)")

    def test_zombie_timeout_parks_instead_of_reaping(self) -> None:
        timeout = self.one_uaf.index("code <= 0")
        reap = self.one_uaf.index("waitpid(child, &status, 0)")
        block = self.one_uaf[timeout:reap]
        self.assertIn("victim_watch_forever()", block)
        self.assertIn('V_UNPROVEN', block)
        self.assertIn('native_state("NO_ROOT")', block)
        self.assertIn('waitid_failed', block)

    def test_waitpid_failure_remains_unproven(self) -> None:
        reap = function_body(self.source, "victim_reap")
        self.assertIn("r != v->pid", reap)
        self.assertIn("reap_waitpid_failed", reap)
        self.assertIn("V_UNPROVEN", reap)
        self.assertLess(reap.index("reap_waitpid_failed"),
                        reap.index("reaped_after_proven"))
        self.assertRegex(reap, r"errno\s*==\s*EINTR")

    def test_preflight_exit_status_matches_verdict(self) -> None:
        preflight = function_body(self.source, "preflight")
        self.assertIn("static int preflight(int quick)", self.source)
        self.assertIn('rc = 2;\n\t\tverdict = "blocked"', preflight)
        self.assertIn('rc = 0;\n\t\tverdict = "ok"', preflight)
        self.assertIn('rc = 3;\n\t\tverdict = "inconclusive"', preflight)
        self.assertIn("return rc;", preflight)
        self.assertIn("return preflight(quick);", self.main)
        self.assertNotRegex(self.main, r"preflight\(quick\);\s*return 0;")
        self.assertIn('exit "$RC"', self.runner)
        # Per-kernel engines may intentionally diverge outside this function;
        # enforce the shared preflight verdict/return contract without forcing
        # a whole-file copy from another kernel family.
        expected = function_body(self.source, "preflight")
        for sibling in ("6658", "6689"):
            other = (ROOT / "binary-sources" / sibling / "uaf_plant_61258.c").read_text(encoding="utf-8")
            self.assertEqual(function_body(other, "preflight"), expected,
                             f"shared preflight contract diverged: {sibling}")

    def test_native_terminal_state_drives_proof(self) -> None:
        self.assertEqual(self.runner.count("PC98260_STATE_FILE=$STATE"), 2)
        self.assertIn('STATE=$D/98260-$RUN_ID.state', self.runner)
        self.assertLess(self.runner.index('RUN_ID="$(date'),
                        self.runner.index('STATE=$D/98260-$RUN_ID.state'))
        self.assertIn('FAIL=native_state_reset_failed', self.runner)
        self.assertIn('NO_ROOT)', self.runner)
        self.assertIn('native_fail native_no_root_terminal', self.runner)
        self.assertIn('native_not_terminal_after_${PROOF_WAIT}s', self.runner)
        self.assertIn('98260_NATIVE_STILL_RUNNING=1', self.runner)
        self.assertNotIn('no_rootd_socket_after_240s', self.runner)
        self.assertNotIn('UAF_STARTED', self.runner)
        fail = function_body(self.runner, "native_fail")
        self.assertIn('if [ "$UAF_ARMED" = "1" ]', fail)
        self.assertIn('98260_PRE_ARM_EXIT=1', fail)
        self.assertIn('98260_PRE_ARM_RUNNING=1', fail)
        state = function_body(self.source, "native_state")
        self.assertIn('rename(tmp, path)', state)
        self.assertIn('native_state("ARMED") != 0', self.source)
        self.assertLess(self.one_uaf.index('if (!v)'),
                        self.one_uaf.index('arm_ready, 1'))
        self.assertLess(self.runner.index('98260_LOG=$LOG'),
                        self.runner.index('PC98260_STATE_FILE=$STATE'))

    def test_uid_phase_uses_fake_cred_layout_without_cap_tile(self) -> None:
        # The 6.12 fake-cred baseline used CRED + SELINUX + NONE.  Do not carry
        # the later self-parent PLANT_PTR cap tile in the same reclaim: cap has
        # its own previously verified pass and must prove bit16 before finit.
        pick = function_body(self.source, "pick_triple")
        self.assertNotIn("g_want_cap", self.source)
        self.assertIn("if (g_cap_mode && !(slab & 0x10000))", pick)
        self.assertIn("g_tile_kind[2] = TILE_NONE", pick)
        self.assertNotIn("cap plant combined", self.main)
        rooted = self.main.index("if (!rooted)")
        separate = self.main.index("for (int i = 0; i < 8", rooted)
        self.assertLess(rooted, separate)
        self.assertIn("reclaim failed before verify", self.source)

    def test_resolved_teardown_clears_unproven_marker(self) -> None:
        # 2026-11-14 00:15: every victim was reaped (native summary unproven=0)
        # but the previous boot's marker stayed on disk and the wrapper
        # reported unproven=1.  The resolved teardown must sync the marker,
        # startup must prune a marker from another boot, and the runner must
        # ignore a stale-boot marker for SOFT_REBOOT_SAFE.
        for path in (self.source,
                     (ROOT / "binary-sources/6658/uaf_plant_61258.c").read_text(encoding="utf-8")):
            finish = function_body(path, "victim_finish_or_watch")
            self.assertIn("unproven_marker_sync();", finish)
            self.assertIn("unproven_marker_prune_stale", path)
            self.assertLess(path.index("unproven_marker_prune_stale();"),
                            path.index("trace_buf_prewarm();"))
        self.assertIn("98260_UNPROVEN_MARKER=stale", self.runner)
        self.assertIn('if [ "$_unp_boot" != "$BOOT_ID" ]', self.runner)

    def test_victim_slab_must_be_fully_owned(self) -> None:
        # A victim slab that still holds another process's k_itimer never
        # empties, so its page never reaches the buddy and the reclaim waits
        # out every attempt (g893 23:44 run: 7/7 page_freed=0).  The timer
        # capture must keep only the child's own allocations (pid filter), the
        # triple must prefer the fullest middle slab, and a raw id/layout miss
        # must fall back to the name-based text scan with a diagnostic.
        sources = [self.source,
                   (ROOT / "binary-sources/6658/uaf_plant_61258.c").read_text(encoding="utf-8"),
                   (ROOT / "binary-sources/6689/uaf_plant_61258.c").read_text(encoding="utf-8")]
        for text in sources:
            pick = function_body(text, "pick_triple")
            # g893 08:21 proved 16 object starts per 4 KiB page at stride
            # 0x108 while the 16th straddles the boundary, i.e. one 8 KiB
            # slab.  Score the whole slab, never a single 4 KiB page.
            self.assertIn("owned slab=", pick)
            self.assertIn("owned_n", pick)
            self.assertIn("(g_all[j] & ~UINT64_C(0x1fff))", pick)
            self.assertNotIn("(g_all[j] & ~UINT64_C(0xfff))", pick)
            cap = function_body(text, "collect_nth")
            self.assertIn("timer_tid", text)
            self.assertIn("want_tid", cap)
            self.assertIn("pid != want_tid", cap)
            self.assertIn("static int find_page_free_text(", text)
            self.assertIn("raw_diag_free", text)
            self.assertIn("text fallback page_freed", text)
            # The order-0 half reclaim must accept a single-page allocation
            # from a spray worker (the old order>=1 rule could never match).
            self.assertIn("static int find_page_alloc_page(", text)
            # Sequential mode (raw trace unavailable) sprays from the main
            # thread, so the single-page matcher must accept both the main pid
            # and the fast workers, and any allocation covering the page.
            self.assertIn("raw_pid_is_spray", text)
            page_fn = function_body(text, "find_page_alloc_page")
            raw_page = function_body(text, "raw_find_alloc_page")
            self.assertIn("raw_pid_is_ours(pid)", raw_page)
            self.assertIn("trace_task_is_self(t->line)", page_fn)
            # 2026-11-14 09:35 AP_S_PANIC: an order-2 block was accepted as
            # proof, but it holds two 8 KiB objects and the trace cannot say
            # which one our datagram took.  Only provably aligned objects may
            # count: order-1 slab at the base, or order-0 page at the pfn.
            self.assertIn("order != 1 || head != base", text)
            self.assertIn("order != 0 || head != pfn", text)
            self.assertNotIn("head + (UINT64_C(1) << order) < base + 2", text)
            half = function_body(text, "reclaim_stream_half")
            self.assertIn("find_page_alloc_page(free_pfn, free_cpu)", half)
        self.assertEqual(
            (ROOT / "binary-sources/6658/uaf_plant_61258.c").read_text(encoding="utf-8"),
            (ROOT / "binary-sources/6689/uaf_plant_61258.c").read_text(encoding="utf-8"),
            "6658/6689 sources must stay byte-identical")

    def test_zero_residual_exit_allows_same_boot_retry(self) -> None:
        # Shark v2.4 zero-residual: when a failed run has no OPEN/UNPROVEN
        # victim and never installed a fake cred, the plant exits without a
        # holder (code 13) and the runner skips the parked marker so a
        # same-boot retry is allowed.  A fake cred page always keeps the
        # holder: task->cred points into it.
        sources = [self.source,
                   (ROOT / "binary-sources/6658/uaf_plant_61258.c").read_text(encoding="utf-8"),
                   (ROOT / "binary-sources/6689/uaf_plant_61258.c").read_text(encoding="utf-8")]
        for text in sources:
            self.assertIn("g_fake_installed", text)
            self.assertEqual(text.count("ZERO_RESIDUAL=1"), 2)
            self.assertIn("_open == 0 && !g_fake_installed", text)
            self.assertIn("_exit(13);", text)
            self.assertIn("g_fake_installed = 1;", text)
        self.assertIn("98260_ZERO_RESIDUAL=1", self.runner)
        self.assertIn("same-boot retry allowed", self.runner)
        self.assertIn("UAF_ARMED=0", self.runner)

    def test_miss_chase_is_bounded_and_strict(self) -> None:
        # Shark v2.4 P4 transplant: after the burst loses the victim page the
        # zombie is kept and a bounded chase waits for the pfn to return to
        # the buddy, sprays rounds, and only a strict self-owned allocation
        # (order-1 at base / order-0 at pfn) counts.  A give-up must still
        # fall through to victim_eval_miss and the watcher.
        sources = [self.source,
                   (ROOT / "binary-sources/6658/uaf_plant_61258.c").read_text(encoding="utf-8"),
                   (ROOT / "binary-sources/6689/uaf_plant_61258.c").read_text(encoding="utf-8")]
        for text in sources:
            chase = function_body(text, "victim_chase")
            self.assertIn("PC98260_CHASE_MS", chase)
            self.assertIn("PC98260_CHASE_ROUNDS", chase)
            self.assertIn("PC98260_CHASE_WAIT_MS", chase)
            self.assertIn("PC98260_CHASE_POST", chase)
            self.assertIn("find_page_alloc(node_pfn, free_cpu)", chase)
            self.assertIn("find_page_alloc_page(node_pfn, free_cpu)", chase)
            self.assertIn("never truncate the ring", chase)
            self.assertIn("[chase] gave up", chase)
            self.assertIn(
                "hit = victim_chase(v, pat, base, node_pfn, free_cpu);",
                text)
        self.assertEqual(
            (ROOT / "binary-sources/6658/uaf_plant_61258.c").read_text(encoding="utf-8"),
            (ROOT / "binary-sources/6689/uaf_plant_61258.c").read_text(encoding="utf-8"),
            "6658/6689 sources must stay byte-identical")

    def test_slide_measure_accepts_64k_aligned_kaslr(self) -> None:
        # ARM64 6.6+ relocatable kernels use MIN_KIMG_ALIGN = SZ_64K, so the
        # measured slide can be 64 KiB aligned (e.g. 0x18e1280000 on
        # 6.6.118-g893).  A 2 MiB requirement rejected real slides and the
        # run aborted with "measurement did not converge" (2026-11-13 log).
        for path in (self.source,
                     (ROOT / "binary-sources/6658/uaf_plant_61258.c").read_text(encoding="utf-8"),
                     (ROOT / "binary-sources/6689/uaf_plant_61258.c").read_text(encoding="utf-8")):
            self.assertIn("#define SLIDE_ALIGN UINT64_C(0x10000)", path)
            self.assertNotIn("#define SLIDE_ALIGN UINT64_C(0x200000)", path)
            once = function_body(path, "measure_slide_once")
            # An unaligned record must not shadow a later aligned one: keep
            # scanning and only fall back when no aligned candidate exists.
            self.assertIn("unaligned_fallback", once)
            self.assertIn("if (!slide)\n\t\t\tslide = unaligned_fallback;", once)
            self.assertNotIn("slide = site - TIMER_LINK;\n\t\t\t\tbreak;", once)

    def test_armed_triple_stays_in_one_4k_half(self) -> None:
        # The reclaim hit proves only base 0's 4 KiB half.  A triple whose
        # armed nodes straddle both halves leaves the far half holding the
        # released slab's bytes, so the reaped node's rb_erase walks garbage
        # and faults -> page_request panic (seen in the 2026-11-11 22:09 run).
        pick = function_body(self.source, "pick_triple")
        self.assertIn("(g_tile_off[0] ^ g_tile_off[1]) & 0x1000", pick)
        self.assertIn("(g_tile_off[0] ^ g_tile_off[2]) & 0x1000", pick)
        # Defense in depth: the ledger must demand every armed node's half,
        # including TILE_NONE nodes, not just the planted tiles.
        reg = function_body(self.source, "victim_reg")
        self.assertIn("v->need |= 1u << (g_tile_off[b] >> 12);", reg)
        self.assertNotIn("if (g_tile_kind[b] != TILE_NONE)", reg)

    def test_fake_cred_branch_is_reachable_and_separate(self) -> None:
        fake = self.main.index("if (g_no_real_cred)")
        real = self.main.index("[mode] real-cred", fake)
        branch = self.main[fake:real]
        self.assertLess(fake, self.main.index("leak_real_cred()"))
        self.assertIn("[mode] fake-cred", branch)
        self.assertIn("leak_task()", branch)
        self.assertIn("start_child_ksu()", branch)
        self.assertNotIn("cap_effective", branch)
        self.assertIn('REAL_CRED_ARG="--no-real-cred"', self.runner)
        self.assertIn('REAL_CRED_ENV="PC98260_ROOTD=1"', self.runner)
        self.assertIn('REAL_CRED_NATIVE=0', self.runner)
        self.assertIn('CRED_MODE=${MAGICROOT_98260_CRED_MODE:-fake}', self.runner)
        self.assertIn('MAGICROOT_98260_CRED_MODE=" + ui.getCredMode()', self.controller)
        fake_load = self.runner.index('elif [ "$CRED_MODE" = "fake" ]; then',
                                      self.runner.index('if [ "$KSU_ENABLE" = "1" ]'))
        real_load = self.runner.index('elif [ -z "$SLIDE" ]', fake_load)
        fake_block = self.runner[fake_load:real_load]
        self.assertIn("98260_FAKE_LATELOAD_BEGIN", fake_block)
        self.assertIn("patch_init_cred_module_98260", fake_block)
        self.assertIn("98260_INIT_CRED_INSMOD_BEGIN", fake_block)
        self.assertLess(fake_block.index("patch_init_cred_module_98260"),
                        fake_block.index("run_fake_late_load\n"))
        self.assertIn('[ "${MAGICROOT_98260_PREFLIGHT:-0}" != "1" ]', self.runner)

    def test_manager_pair_is_strict_and_packages_list_is_untouched(self) -> None:
        for text in (self.runner, self.root_stage):
            self.assertNotIn("/data/system/packages.list", text)
        self.assertIn("98260_MANAGER_PAIR=strict", self.runner)
        self.assertIn("FAIL=98260_manager_pair_missing", self.runner)
        self.assertIn('late-load --kmi', self.runner)
        self.assertIn("--package-name", self.runner)
        self.assertIn("98260_MANAGER_PACKAGES=untouched", self.runner)
        self.assertIn('[ "$DUAL_CRED_AVAILABLE" = "1" ]', self.runner)
        self.assertNotIn("98260_fake_cred_unsupported", self.runner)
        self.assertIn("FAIL=manager_pair_missing", self.controller)
        self.assertIn("norc=1", self.runner)
        self.assertIn("preinit=0", self.runner)
        self.assertIn("grep -aq 'parm=norc'", self.runner)
        self.assertIn("grep -aq 'parm=preinit'", self.runner)

    def test_soft_reboot_guard_is_root_verified_and_opt_in(self) -> None:
        marker = function_body(self.source, "unproven_marker_sync")
        self.assertIn("fsync(fd)", marker)
        self.assertIn('open("/data/local/tmp", O_RDONLY | O_DIRECTORY', marker)
        self.assertIn("test -d /data/adb/ksu/soft_reboot.lock", self.runner)
        self.assertIn("verified=root", self.runner)
        self.assertIn("98260_SOFT_REBOOT_SAFE=0", self.runner)
        self.assertIn("invalid_marker_with_live_plant", self.hotfix)
        # FinaSU/other flavors need ksud soft-reboot for post-fs-data/
        # services, so the lock must be opt-in and never forced by kernel.
        self.assertIn(
            "SOFT_REBOOT_GUARD_DEFAULT=${MAGICROOT_SOFT_REBOOT_GUARD:-0}",
            self.runner)
        self.assertNotIn("6.12.*|6.18.*) SOFT_REBOOT_GUARD_DEFAULT=1",
                         self.runner)
        self.assertIn('fullLog.contains("98260_SOFT_REBOOT_SAFE=0")', self.controller)
        self.assertIn("提权完成 · 软重启有风险", self.controller)
        self.assertIn("提权完成，但软重启有风险", self.controller)

    def test_live_log_survives_process_or_soft_reboot(self) -> None:
        # onekeyjb reference: per-line sync plus startup tail recovery.  Our
        # implementation is a separate pure-Java store with a real JVM test.
        self.assertIn('new LiveLogStore(new File(', self.controller)
        self.assertIn('externalFiles != null ? externalFiles : getFilesDir()', self.controller)
        self.assertIn('"magicroot-live.log"', self.controller)
        self.assertIn("liveLogStore.readTail(400)", self.controller)
        self.assertIn("store.append(line)", self.controller)
        self.assertIn("store.reset(", self.controller)
        self.assertIn("persistLiveLog(line);", self.controller)
        self.assertIn("liveLogWriter.shutdown()", self.controller)

    def test_cap_failure_never_calls_finit_or_waits_forever(self) -> None:
        # 16:32 run: uid0 landed, all eight cap attempts missed, then finit
        # returned EPERM and the UI kept waiting.  Fail closed before delivery.
        self.assertIn("FAIL=cap_sys_module_not_achieved", self.source)
        cap = self.main.index("cap_ok ? \"has CAP_SYS_MODULE\"")
        blocked = self.main.index("FAIL=cap_sys_module_not_achieved", cap)
        self.assertLess(blocked, self.main.index("start_child_ksu()", blocked))
        self.assertIn("FAIL=98260_cap_sys_module_not_achieved", self.runner)
        self.assertIn("FAIL=98260_finit_module_error", self.runner)

    def test_selinux_hide_ui_value_is_logged_and_applied(self) -> None:
        # The 20:36 successful SukiSU log proved feature rc=0, while failed
        # runs stopped before the feature tail.  Keep the requested value in
        # 98260_OPTIONS so a future failure log still proves the UI mapping.
        self.assertIn('MAGICROOT_SELINUX_HIDE=" + (selinuxHide ? "1" : "0")',
                      self.controller)
        self.assertIn('SELINUX_HIDE_98260=${MAGICROOT_SELINUX_HIDE:-1}',
                      self.runner)
        self.assertIn('selinux_hide=$SELINUX_HIDE_98260', self.runner)
        feature = function_body(self.runner, "feature_set_98260")
        self.assertIn('feature set $_f_name $_f_value', feature)
        self.assertIn('feature_set_98260 selinux_hide "$SELINUX_HIDE_98260"',
                      self.runner)

    def test_ksu_finish_reaches_post_load_feature_tail(self) -> None:
        # Regression: finish_ksu_loaded() exited after the first Fina load, so
        # selinux_hide stayed disabled despite the UI requesting it, and the
        # log contained neither KSU_SU_WAIT nor any 98260_FEATURE_* result.
        finish = function_body(self.runner, "finish_ksu_loaded")
        self.assertIn("return 0", finish)
        self.assertNotIn("exit 0", finish)
        self.assertNotIn("98260_SUCCESS=1", finish)
        self.assertIn("KSU_REUSED_98260=$_f_reused", finish)
        loaded = self.runner.index('finish_ksu_loaded "$KSU_METHOD" 0')
        wait = self.runner.index('echo "98260_KSU_SU_WAIT=', loaded)
        cleanup = self.runner.index('echo "98260_CLEANUP=ok reason=ksu_loaded"', wait)
        feature = self.runner.index("feature_set_98260 selinux_hide", cleanup)
        enforcing = self.runner.index("98260_SELINUX_FINAL=", feature)
        success = self.runner.index(
            'echo "98260_SUCCESS=1 reused=${KSU_REUSED_98260:-0}"', enforcing)
        self.assertLess(loaded, wait)
        self.assertLess(wait, cleanup)
        self.assertLess(cleanup, feature)
        self.assertLess(feature, enforcing)
        self.assertLess(enforcing, success)
        self.assertIn('if [ "$KSU_SU_READY" != "1" ]',
                      self.runner[wait:cleanup])

    def test_real_cred_capture_failure_fails_fast(self) -> None:
        # A cred-capture miss happens before any UAF; it cannot recover by
        # waiting.  The old loop only treated "missed page" as fatal and kept
        # the UI at 98% for the full PROOF_WAIT (720 s) after the native
        # process had already exited.
        self.assertIn("real cred leak failed", self.runner)
        self.assertIn("FAIL=98260_real_cred_capture", self.runner)
        self.assertIn("FAIL=98260_native_exited_before_ksu", self.runner)
        loop = self.runner.index(
            "98260_REAL_CRED_INPROC_FINIT_READY path=$PATCHED")
        capture = self.runner.index(
            "98260_KSU=failed reason=real_cred_capture", loop)
        self.assertLess(capture, self.runner.index("sleep 1", capture))
        exited = self.runner.index(
            "98260_KSU=failed reason=native_exited", loop)
        self.assertLess(exited, self.runner.index("sleep 1", exited))

    def test_cred_diag_is_read_only_and_reports_evidence(self) -> None:
        # --diag-cred arms the same kmem trace and mints a child cred, but
        # never writes creds or starts the UAF.  Its evidence must include
        # raw bytes, observed call sites, implied slides and pid matches.
        self.assertIn("--diag-cred", self.source)
        self.assertIn("[cred-diag]", self.source)
        for needle in ("expected_cred_site", "expected_timer_site",
                       "raw_bytes", "implied_slide", "pid_hits"):
            self.assertIn(needle, self.source)
        # The diagnostic must return before leak_real_cred/UAF starts.
        diag_call = self.main.index("return diag_cred_once()")
        leak = self.main.index("leak_real_cred()")
        self.assertLess(diag_call, leak)

    def test_cred_arm_verifies_through_trigger_not_enable_file(self) -> None:
        # Regression (rc14): the arm guard read
        # events/kmem/kmem_cache_alloc/enable, which the shell domain cannot
        # open on Android (EACCES with SELinux enforcing, even though the
        # trigger file is writable), so every run aborted before the capture
        # with "kmem event not enabled after trigger".
        body = function_body(self.source, "leak_real_cred_once")
        self.assertIn("cred_trigger_armed()", body)
        self.assertNotIn("kmem_cache_alloc/enable", body)
        trigger = function_body(self.source, "cred_trigger_armed")
        self.assertIn("rss_stat/trigger", trigger)
        self.assertIn("enable_event:kmem:kmem_cache_alloc", trigger)

    def test_inproc_wait_fails_fast_when_plant_parks(self) -> None:
        # Without this the UI waits the full PROOF_WAIT even though the plant
        # already gave up (all attempts missed) and parked.
        self.assertIn("missed page; holding zombie", self.runner)
        self.assertIn("98260_KSU=failed reason=root_not_achieved", self.runner)
        wait = self.runner.index("98260_REAL_CRED_INPROC_FINIT_READY")
        self.assertLess(wait, self.runner.index("reason=root_not_achieved", wait))

    def test_real_cred_manager_registration(self) -> None:
        # direct-finit loads the manager-extracted LKM in-process to preserve
        # CAP_SYS_MODULE.  Once su works, that same manager's ksud late-load
        # sees the live module and performs only its userspace stages.
        self.assertIn("register_manager_98260()", self.runner)
        registration = function_body(self.runner, "register_manager_98260")
        self.assertIn("late-load --kmi", registration)
        self.assertIn("--package-name", registration)
        self.assertIn("98260_MANAGER_LATELOAD_RC", registration)
        self.assertIn("98260_MANAGER_PACKAGES=untouched", registration)
        self.assertNotIn("chmod", registration)
        self.assertNotIn("packages.list", registration)
        self.assertNotIn("dynamic set-apk", registration)
        self.assertLess(
            self.runner.index("98260_REAL_CRED_SU_PROOF"),
            self.runner.index("register_manager_98260 || true"),
            "manager late-load userspace setup must follow the su proof",
        )
        # Root-stage legacy callers retain their dynamic-manager registration,
        # but no longer use it as an excuse to modify PackageManager state.
        self.assertIn("dynamic set-apk", self.root_stage)
        self.assertIn("dynamic grant", self.root_stage)
        self.assertIn("ROOT_STAGE_DYNAMIC_GRANT_RC", self.root_stage)

    def test_manager_registration_never_changes_package_database(self) -> None:
        registration = function_body(self.runner, "register_manager_98260")
        root_registration = function_body(self.root_stage, "register_manager")
        for body in (registration, root_registration):
            self.assertNotIn("/data/system/packages.list", body)
            self.assertNotIn("chmod 0644", body)
            self.assertNotIn("packages.list.magicroot", body)
            self.assertNotIn("CROWN_TRIGGER=packages_list", body)
        self.assertIn("refresh_manager_98260 \"$_rm_pkg\"", registration)
        self.assertIn("anon_inode:\\[ksu_driver\\]", self.runner)
        self.assertIn("98260_MANAGER_CONNECTED=1", self.runner)
        self.assertIn("ROOT_STAGE_PACKAGES=untouched", root_registration)

    def test_sweep_never_reaps_without_self_cover(self) -> None:
        # Repeated AP_S_PANIC: victim_sweep() reaped OPEN victims whose free
        # was not fully observed.  A half can be foreign-owned while the trace
        # ring truncates the evidence, so reaping is only safe after the
        # watcher proves our own zero page covers every needed half.
        sweep = function_body(self.source, "victim_sweep")
        self.assertIn("unproven_reap_refused", sweep)
        self.assertNotIn("reaping stale nodes", sweep)
        self.assertNotIn("victim_reap(v);", sweep.split("unproven_reap_refused")[-1])

    def test_mintwait_exec_inherits_environment(self) -> None:
        # Regression: cred_child used a fixed envp, so the execed mintwait lost
        # PC98260_FINIT_* and silently fell back to exec'ing sh (uid 0 zombie,
        # no module load).  The child must inherit environ.
        child = function_body(self.source, "cred_child")
        self.assertIn('execve("/proc/self/exe", argv, environ)', child)
        self.assertNotIn("char *const envp[]", child)

    def test_real_cred_inproc_finit_path(self) -> None:
        # This ROM's vendor LSM blocks a real-cred process from binding the
        # listener socket (EACCES), so KSU must load in the mintwait child
        # itself, before any exec can drop CAP_SYS_MODULE from the bounding set.
        self.assertIn("SYS_finit_module", self.source)
        mint = function_body(self.source, "mintwait_main")
        for needle in ("PC98260_FINIT_KO", "PC98260_FINIT_READY",
                       "PC98260_FINIT_PARAMS_FILE", "PC98260_FINIT_EXIT"):
            self.assertIn(needle, mint)
        self.assertIn("PC98260_FINIT_KO=", self.runner)
        self.assertIn("PC98260_FINIT_READY=", self.runner)
        self.assertIn("98260_REAL_CRED_INPROC=1 proof=module_load", self.runner)
        self.assertIn("98260_REAL_CRED_KO_READY=", self.runner)
        self.assertIn("KSU_METHOD=real-cred-inproc", self.runner)
        self.assertIn("98260_REAL_CRED_INPROC_OK=1", self.runner)
        # The ready marker must be published only after the vermagic check.
        self.assertLess(self.runner.index("98260_KSU_PATCH_RC="),
                        self.runner.index("98260_REAL_CRED_KO_READY="))

    def test_unproven_marker_blocks_any_second_plant(self) -> None:
        # Direct development payloads may be named plant_rc*/plant_test; the
        # boot-scoped victim ledger must guard even when comm-based checks miss.
        self.assertIn("UNPROVEN_MARKER=/data/local/tmp/.magicroot-unproven", self.runner)
        self.assertIn('[ "$_unproven_boot" = "$BOOT_ID" ]', self.runner)
        self.assertIn("98260_unproven_victims_reboot_required", self.runner)
        guard = self.runner.index("98260_unproven_victims_reboot_required")
        self.assertLess(self.runner.index("parked_check"), guard)
        self.assertLess(guard, self.runner.index("pidof exploit-android-key-ptr", guard))

    def test_rootd_reuse_precedes_new_plant_rejection(self) -> None:
        reuse = self.runner.index('98260_SUCCESS=1 reused=1')
        parked = self.runner.index('\nparked_check\n', reuse)
        reject = self.runner.index('FAIL=rootd_live_without_usable_socket', reuse)
        self.assertLess(reuse, parked)
        self.assertLess(parked, reject)
        self.assertIn('verify_credential_fields', self.runner[reuse - 300:reuse])

    def test_no_real_cred_proof_checks_effective_ids(self) -> None:
        proof = function_body(self.runner, "verify_credential_fields")
        self.assertIn('"$REAL_CRED_ARG" = "--no-real-cred"', proof)
        self.assertIn('$3 != 0 || $4 != 0 || $5 != 0', proof)
        self.assertIn('real-cred', self.runner)
        self.assertIn('effective_saved_fs_ids=0 real_ids=informational', self.runner)
        self.assertNotIn('FAIL=proof real_uid_not_zero', self.runner)

    def test_no_real_cred_proof_runtime_cases(self) -> None:
        proof = function_body(self.runner, "verify_credential_fields")
        script = ("verify_credential_fields() {\n" + proof + "\n}\n"
                  "REAL_CRED_ARG=$1 VERIFY=$2 verify_credential_fields\n")
        with tempfile.TemporaryDirectory() as td:
            sample = Path(td) / "verify"
            sample.write_text("Uid:\t2000\t0\t0\t0\nGid:\t2000\t0\t0\t0\n")
            def run(mode: str) -> int:
                return subprocess.run(
                    ["sh", "-c", script, "sh", mode, str(sample)],
                    check=False, capture_output=True).returncode
            self.assertEqual(run("--no-real-cred"), 0)
            self.assertNotEqual(run(""), 0)
            sample.write_text("Uid:\t2000\t2000\t0\t0\nGid:\t2000\t0\t0\t0\n")
            self.assertNotEqual(run("--no-real-cred"), 0)
            sample.write_text("Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n")
            self.assertEqual(run(""), 0)

    def test_export_contains_only_current_complete_native_log(self) -> None:
        self.assertIn(': > "$LOG"', self.runner)
        self.assertIn('98260_NATIVE_BEGIN run=$RUN_ID boot=$BOOT_ID', self.runner)
        self.assertIn('98260_PAYLOAD_SHA256=', self.runner)
        export = function_body(self.controller, "diagnosticLogLoop")
        self.assertIn("cat \" + WORK + \"/98260.log", export)
        self.assertIn("98260_LOG=", export)
        self.assertIn("98260_H1C_BEGIN", export)

    def test_zygisk_next_state_dir_is_restored_without_clearing_state(self) -> None:
        self.assertIn('ZN_STATE_DIR=/data/adb/zygisksu', self.hotfix)
        self.assertIn('mkdir -p "$ZN_STATE_DIR"', self.hotfix)
        self.assertIn('ZYGISK_STATE=ready', self.hotfix)
        self.assertIn('reason=already_running', self.hotfix)
        self.assertIn('FINAL_ZYGISK_NEXT=', self.hotfix)
        self.assertIn('PID,STAT,NAME', self.hotfix)
        self.assertIn("$2 !~ /^Z/", self.hotfix)
        self.assertIn('*service-stage*', self.hotfix)
        self.assertLess(self.hotfix.index('mkdir -p "$ZN_STATE_DIR"'),
                        self.hotfix.index('timeout 45 "$KSUD" post-fs-data'))
        # The state directory itself must never be removed blindly; only a
        # recorded abort marker may be cleared when the module's own rule exists.
        self.assertNotRegex(self.hotfix, r'rm\s+-[rf]*\s+"?\$ZN_STATE_DIR"?(\s|$)')
        self.assertNotRegex(self.hotfix, r'rm\s+-rf\s+[^\n]*ZN_STATE_DIR')

    def test_zygisk_provider_is_detected_before_repair(self) -> None:
        # Zygisk is pluggable (KSU FolkZygisk / Zygisk Next / YukiZygisk ...).
        # The ZN-specific repair must be gated on ksud reporting zygisksu.
        self.assertIn('"$KSUD" zygisk status', self.hotfix)
        self.assertIn('ZYGISK_PROVIDER=engine=', self.hotfix)
        self.assertIn('reason=provider_not_zygisksu', self.hotfix)
        self.assertIn('reason=sepolicy_rule_missing', self.hotfix)
        self.assertLess(self.hotfix.index('"$KSUD" zygisk status'),
                        self.hotfix.index('mkdir -p "$ZN_STATE_DIR"'))

    def test_zygisk_next_sepolicy_is_never_auto_restored(self) -> None:
        rule = ROOT / "main/app/assets/zygisknext-sepolicy-1.5.3.rule"
        self.assertFalse(rule.exists(), "MagicRoot must not bundle a sepolicy rule")
        for token in ("zygisknext-sepolicy", "MAGICROOT_ZN_SEPOLICY", "ZN_RULE_SRC"):
            self.assertNotIn(token, self.hotfix)
            self.assertNotIn(token, self.controller)
        self.assertIn('ZYGISK_SEPOLICY=present source=module', self.hotfix)
        self.assertIn('reason=module_rule_required', self.hotfix)
        self.assertIn('ZYGISK_MODULE_RECOVERED=reenabled', self.hotfix)
        self.assertIn('ZYGISK_STATE_RESET=abort_cleared', self.hotfix)
        # Never start zygiskd without the module's own rule; never repair the
        # module's abort state while that verified input is absent.
        self.assertLess(self.hotfix.index('-f "$ZYGISKDIR/sepolicy.rule"'),
                        self.hotfix.index('ZYGISKD_RESTART=done'))

    def test_post_arm_miss_never_reaps_the_victim(self) -> None:
        armed = self.one_uaf.index("memory_order_release);", self.one_uaf.index("phase, 4"))
        zombie_wait = self.one_uaf.index("wait_zombie(child", armed)
        span = self.one_uaf[armed:zombie_wait]
        # The only raw reap in the post-arm/miss span is the kill-guarded
        # error branch; every other waitpid on an armed victim goes through
        # victim_reap() once the slab owner is proven.
        for match in re.finditer(r"waitpid\(child", span):
            prefix = span[max(0, match.start() - 300):match.start()]
            self.assertIn("kill(child, SIGKILL)", prefix,
                          "post-arm reap must be preceded by an explicit kill")

    def test_armed_victims_are_ledgered_and_proven_before_reaping(self) -> None:
        self.assertIn("victim_reg(child, victim)", self.one_uaf)
        self.assertIn("victim_reap(v)", self.source)
        self.assertIn("victim_eval_miss(v)", self.reclaim_stream)
        self.assertLess(
            self.reclaim_stream.index("victim_eval_miss(v)"),
            self.reclaim_stream.rindex("quiet_reclaim_trace()"),
            "miss classification must run while the reclaim trace buffer is still live",
        )
        self.assertIn("victim_sweep()", self.main)
        self.assertIn("victim_summary()", self.main)
        self.assertLess(self.main.index("victim_sweep()"),
                        self.main.index("start_child_ksu()"),
                        "open victims must be resolved before success parks")

    def test_hotfix_guards_unproven_victims_before_zygote_kill(self) -> None:
        # The hotfix must not restart zygote while a previous 98260 run left
        # unproven armed zombies; doing so panics via init's reap.  It should
        # wait for the device-side marker to clear (watch_forever), then only
        # refuse as a last resort.
        self.assertIn("UNPROVEN=/data/local/tmp/.magicroot-unproven", self.hotfix)
        self.assertIn("VICTIM_GUARD=waiting", self.hotfix)
        # The guard now waits and warns instead of refusing the repair.
        self.assertIn("VICTIM_GUARD=warn", self.hotfix)
        self.assertNotIn("exit 9", self.hotfix)
        self.assertLess(self.hotfix.index("VICTIM_GUARD=waiting"),
                        self.hotfix.index('kill -9 "$ZPID"'),
                        "victim guard must run before the zygote kill")

    def test_parked_parent_watches_unproven_victims(self) -> None:
        self.assertIn("victim_watch_forever", self.source)
        # Every park site must route through the watcher, not a bare pause():
        # a foreign-covered page can cycle back to the buddy and be reclaimed.
        pause_sites = len(re.findall(r"for\s*\(\s*;;\s*\)\s*pause\s*\(\s*\)", self.main))
        watch_sites = self.main.count("victim_watch_forever()")
        self.assertGreaterEqual(watch_sites, 2)
        self.assertEqual(pause_sites, 0,
                         "parked parent must keep watching, never a bare pause")

    def test_never_freed_victims_are_not_reaped_by_sweep(self) -> None:
        # Hardware evidence (2026-11-09, three AP_S_PANIC reboots): with
        # several missed attempts, sweep's "never fully freed -> reap" branch
        # walked a corrupted tree.  Only the watcher may reap, and only after
        # self-cover proves our zero page owns every needed half.
        sweep = function_body(self.source, "victim_sweep")
        self.assertIn("unproven_reap_refused", sweep)
        self.assertNotIn("reaping stale nodes", sweep)
        watch = function_body(self.source, "victim_watch_forever")
        self.assertIn("cover_self", watch)
        self.assertIn("victim_reap(v)", watch)

    def test_partially_freed_victims_are_never_reaped(self) -> None:
        # No reap may follow the refusal: a freed half can already belong to a
        # foreign owner while the trace ring truncates the evidence.
        sweep = function_body(self.source, "victim_sweep")
        self.assertIn("unproven_reap_refused", sweep)
        tail = sweep.split("unproven_reap_refused")[-1]
        self.assertNotIn("victim_reap(v)", tail)

    def test_sukisu_lateload_patch_is_symbol_locked(self) -> None:
        original = PATCHER.INPUT.read_bytes()
        # The pre-patched output asset is no longer shipped; generate it.
        patched = PATCHER.patch(original)
        self.assertEqual(PATCHER.sha256(original), PATCHER.INPUT_SHA256)
        function_offset = PATCHER.symbol_file_offset(original, PATCHER.FUNCTION)
        offset = function_offset + PATCHER.PATCH_OFFSET
        PATCHER.assert_no_relocation(original, offset)
        self.assertEqual(patched[function_offset:offset], original[function_offset:offset])
        self.assertEqual(patched[offset:offset + 4], PATCHER.AARCH64_RET)
        self.assertEqual(patched[:offset] + patched[offset + 4:], original[:offset] + original[offset + 4:])
        self.assertEqual(PATCHER.sha256(patched), "bf41885860d1c01cef780dc5b31aabf01c8513f090aef264947f426c30f51442")
        damaged = bytearray(original)
        damaged[0] ^= 1
        with self.assertRaises(ValueError):
            PATCHER.patch(bytes(damaged))

    def test_61258_sukisu_uses_lateload_safe_template(self) -> None:
        run = (ROOT / "main/app/assets/98260/run98260.sh").read_text(encoding="utf-8")
        controller = (ROOT / "main/compose-app/app/src/main/java/com/aoki/magicroot/MainActivity.java").read_text(encoding="utf-8")
        # The pre-patched built-in asset and its opt-in switch were removed; the
        # structural auto-patch now runs on the carved manager KO for any flavor.
        self.assertIn('ko-$KSU_FLAVOR_LOCAL-lateload.ko', run)
        self.assertIn('98260_KSU_AUTOPATCH=1', run)
        self.assertIn('SukisuLateLoadPatch.patch(carved)', controller)
        self.assertNotIn('MAGICROOT_BUILTIN_SUKISU', controller)
        self.assertNotIn('ksu-template-sukisu-lateload.ko', controller)

    def test_zygote_injection_path_remains_enabled(self) -> None:
        self.assertIn('kill -9 "$ZPID"', self.hotfix)
        self.assertNotRegex(self.hotfix, r"ksud[^\n]*\bsoft-reboot\b")
        self.assertNotIn("ERROR=zygote_restart_disabled", self.hotfix)

    def test_post_fs_data_is_idempotent_per_boot(self) -> None:
        self.assertIn("PFD_STATE=/data/local/tmp/.magicroot-lsposed-pfd", self.hotfix)
        self.assertIn("POST_FS_DATA_RC=0 skipped=already_done_this_boot", self.hotfix)
        self.assertIn('printf \'%s\\n\' "$CURRENT_BOOT" > "$PFD_STATE.tmp.$$"', self.hotfix)
        self.assertIn('timeout 45 "$KSUD" services', self.hotfix)
        self.assertIn('kill -9 "$ZPID"', self.hotfix)

    def test_lspd_start_waits_for_delayed_process_name(self) -> None:
        # app_process can remain named app_process for several seconds before
        # applying --nice-name=lspd.  Exercise the real shell helper with a fake
        # ps that exposes the old three-second failure and the delayed success.
        functions = (
            "lspd_pid() {\n" + function_body(self.hotfix, "lspd_pid") + "\n}\n"
            + "wait_for_lspd() {\n" + function_body(self.hotfix, "wait_for_lspd") + "\n}\n"
        )
        harness = r'''
set -eu
STATE=$1
DELAY=$2
printf '0\n' > "$STATE"
ps() {
    if [ "$(cat "$STATE")" -ge "$DELAY" ]; then
        printf '4321 lspd\n'
    else
        printf '4321 app_process\n'
    fi
}
sleep() {
    _now=$(cat "$STATE")
    printf '%s\n' "$((_now + 1))" > "$STATE"
}
'''
        harness += functions + r'''
_pid=$(wait_for_lspd 20)
[ "$_pid" = "4321" ]
[ "$(cat "$STATE")" = "$DELAY" ]
'''
        with tempfile.TemporaryDirectory(prefix="magicroot-lspd-wait-") as td:
            state = Path(td) / "ticks"
            for delay in (0, 4):
                run = subprocess.run(
                    ["bash", "-c", harness, "bash", str(state), str(delay)],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_lspd_start_failure_preserves_diagnostics(self) -> None:
        self.assertIn('LSPD_LAUNCHER=$!', self.hotfix)
        self.assertIn('LSPD_START_LOG=', self.hotfix)
        self.assertIn('LSPD_START_LOG_BEGIN', self.hotfix)
        self.assertIn('tail -40 "$LOG.launch"', self.hotfix)
        launch = self.hotfix[self.hotfix.index("java_options="):self.hotfix.index('echo "LSPD_STARTED=')]
        self.assertIn('>>"$LOG.launch" 2>&1 &', launch)
        self.assertNotIn('</dev/null >/dev/null 2>&1 &', launch)


    def test_fake_cred_restores_fullcap_installation_and_guard_scope(self) -> None:
        src = SOURCE.read_text(encoding="utf-8")
        fake = src.split("if (g_no_real_cred) {", 1)[1].split(
            'dprintf(STDOUT_FILENO, "[mode] real-cred', 1)[0]
        self.assertNotIn("if (leak_real_cred())", fake)
        self.assertIn("FAKE_CRED", src)
        self.assertIn("node[0] = g_task + g_cred_slot - 8", src)
        self.assertIn("for (int cap = 48; cap <= 80; cap += 8)", src)
        self.assertIn("slide_addr(LINK_ROOT_USER)", src)
        one = function_body(src, "one_uaf")
        self.assertIn("g_plant_cred && !g_no_real_cred", one)
        self.assertLess(one.index("invalid cred target="), one.index("fork();"))


    def test_real_cred_exits_only_after_all_victims_resolved(self) -> None:
        src = SOURCE.read_text(encoding="utf-8")
        self.assertIn("static void victim_finish_or_watch(void)", src)
        real = src.split('[mode] real-cred', 1)[1]
        self.assertIn("victim_finish_or_watch();", real)
        self.assertIn("victim_watch_forever();",
                      function_body(src, "victim_finish_or_watch"))
        fake = src.split("if (g_no_real_cred) {", 1)[1].split(
            '[mode] real-cred', 1)[0]
        self.assertIn("victim_watch_forever();", fake)


    def test_fast_spray_and_raw_trace_are_bounded_and_revertible(self) -> None:
        src = SOURCE.read_text(encoding="utf-8")
        self.assertIn("static void *fast_spray_worker", src)
        self.assertIn("static int raw_trace_open(void)", src)
        reclaim = function_body(src, "reclaim_stream")
        self.assertLess(reclaim.index("fast_pool_prepare();"),
                        reclaim.index("exec_ready"))
        self.assertIn('env_int("PC98260_FAST_SPRAY", 1, 0, 1)', reclaim)
        self.assertIn("int fast = g_raw_active &&", reclaim)
        self.assertIn('env_int("PC98260_RAW_TRACE", 1, 0, 1)', src)
        self.assertIn("order > 10", function_body(src, "raw_find_alloc"))
        self.assertIn("if (g_raw_active)", function_body(src, "find_page_alloc"))
        self.assertIn("if (g_raw_active)", function_body(src, "find_page_free"))


    def test_fast_path_drains_raw_and_log_sync_is_selective(self) -> None:
        src = SOURCE.read_text(encoding="utf-8")
        self.assertIn("Discard events left by earlier stages", src)
        self.assertIn('strstr(fmt, "[triple] skip cross-half")', src)
        self.assertIn("fdatasync(g_sync_fd)", src)


    def test_fake_cred_accepts_real_uid_before_child_raises_euid(self) -> None:
        src = SOURCE.read_text(encoding="utf-8")
        fake = src.split("if (g_no_real_cred) {", 1)[1].split(
            '[mode] real-cred', 1)[0]
        self.assertNotIn("uid == 0 && euid == 0", fake)
        self.assertIn("uid == 0", fake)
        self.assertIn("euid stays 2000", fake)


    def test_rootd_startup_failure_never_waits_for_socket_timeout(self) -> None:
        run = (ROOT / "main/app/assets/98260/run98260.sh").read_text(encoding="utf-8")
        self.assertIn("rootd\\] (startup failed|bind failed|listen failed)", run)
        self.assertIn("native_fail rootd_startup_failed", run)
        self.assertLess(run.index("rootd\\] (startup failed|bind failed|listen failed)"),
                        run.index("native_not_terminal_after_"))

    def test_all_66_payloads_have_the_full_fake_cred_engine(self) -> None:
        # Regression: the 6658-derived 6.6 payloads used to parse
        # --no-real-cred but fall through to real-cred.  The runner then
        # requested a rootd listener and bind failed with EACCES.
        run = (ROOT / "main/app/assets/98260/run98260.sh").read_text(encoding="utf-8")
        self.assertNotIn("98260_CRED_MODE_FALLBACK=real", run)
        self.assertNotIn("payload_real_engine_only", run)
        for name in ("6658", "6689"):
            src = (ROOT / f"binary-sources/{name}/uaf_plant_61258.c").read_text(
                encoding="utf-8")
            self.assertIn("[mode] fake-cred (rootd + manager late-load)", src)
            self.assertIn("[tile] FAKE_CRED", src)
            self.assertIn("node[0] = g_task + g_cred_slot - 8", src)
            self.assertIn("for (int cap = 48; cap <= 80; cap += 8)", src)
            self.assertIn("skip fake-cred overlap", src)
            self.assertIn("if (g_plant_cred && !g_no_real_cred &&", src)
            one = function_body(src, "one_uaf")
            self.assertIn("if (!g_no_real_cred)\n\t\tclose_stream();", one)
            fake = src.split(
                "if (g_no_real_cred) {\n\t\t/* Explicit fake-cred branch.", 1)[1].split(
                '[mode] real-cred', 1)[0]
            self.assertIn("if (leak_task())", fake)
            self.assertNotIn("if (leak_real_cred())", fake)
            self.assertIn("holding fake-cred pages", fake)
            self.assertIn("victim_watch_forever();", fake)


    def test_legacy_and_special_kernel_families_keep_fake_cred_routes(self) -> None:
        run = self.runner
        self.assertNotIn("98260_fake_cred_unsupported", run)
        self.assertIn('REAL_CRED_ARG="--no-real-cred"', run)
        self.assertIn('REAL_CRED_ENV="PC98260_ROOTD=1"', run)
        # These source-locked 6.6 assets are the old fake-cred payloads; the
        # real-cred direct-finit capability flag must not disable them.
        for name in ("98260-g554", "98260-f171"):
            payload = (ROOT / f"main/app/assets/{name}/exploit-android-key-ptr").read_bytes()
            self.assertIn(b"--no-real-cred", payload)
            self.assertIn(b"[rootd] listening", payload)
            self.assertIn(b"task+cred=", payload)
        h1c = (ROOT / "main/app/assets/98260-h1c/run_h1c.sh").read_text(
            encoding="utf-8")
        self.assertIn("PC98260_ROOTD=1", h1c)
        run6157 = (ROOT / "main/app/assets/98260/run6157_full.sh").read_text(
            encoding="utf-8")
        self.assertIn('[ "$K6157" = "1" ] && REAL_CRED_ARG="--no-real-cred"',
                      run6157)
        run61157 = (ROOT / "main/app/assets/61157/run61157.sh").read_text(
            encoding="utf-8")
        self.assertIn("61157_ROOTD_READY=1", run61157)
        self.assertNotIn("--real-cred", run61157)


    def test_h1c_fake_cred_uses_the_proven_plant_ptr_shape(self) -> None:
        src = (ROOT / "binary-sources/98260-h1c/uaf_plant.c").read_text(
            encoding="utf-8")
        self.assertIn("#define FULLCAP", src)
        self.assertIn("#define H1C_CRED_OFF 0x20u", src)
        self.assertIn("uint64_t page = PAGE_OFFSET + (base << 12);", src)
        # rb_parent = task->cred - 8 makes __rb_change_child() store rb_right
        # (the fake cred pointer) into task->cred.
        self.assertIn("node[0] = g_task + g_task_cred - 8;", src)
        self.assertIn("node[1] = cred_kva;", src)
        self.assertIn("node[2] = 0;", src)
        self.assertIn("cred = (uint64_t *)(pat + node_off + H1C_CRED_OFF);", src)
        self.assertIn("node_off + H1C_CRED_OFF + g_cred_size > blob", src)
        # The forged cred must not overwrite the SELinux blob at 0x1f00.
        self.assertIn("unsigned blob = 0x1f00;", src)
        self.assertIn("static int leak_task(void)", src)
        self.assertNotIn("leak_real_cred", src)
        self.assertNotIn("mintwait_main", src)
        self.assertNotIn("real-cred rooted", src)
        self.assertIn("int rootd_rc = pc98260_run_rootd();", src)
        self.assertIn("[cred] child=%d holding pages", src)
        one = function_body(src, "one_uaf")
        self.assertIn("g_cred_kva = victim + g_kitimer_node + H1C_CRED_OFF;", one)
        after_hit = one.split("if (reclaim_stream(victim, target))", 1)[1]
        self.assertNotIn("close_stream();", after_hit)


    def test_h1c_task_leak_is_drained_sized_multi_candidate(self) -> None:
        src = (ROOT / "binary-sources/98260-h1c/uaf_plant.c").read_text(
            encoding="utf-8")
        self.assertIn("static void drain_raw_trace(void)", src)
        self.assertIn("static uint64_t task_object_size(void)", src)
        self.assertIn("/sys/kernel/slab/task_struct/object_size", src)
        self.assertIn("#define MAX_TASK_CAND 8", src)
        self.assertIn("g_tasks[g_ntasks++] = ptr;", src)
        leak = function_body(src, "leak_task")
        self.assertIn("drain_raw_trace();", leak)
        self.assertLess(leak.index("drain_raw_trace();"),
                        leak.index("enable_event:kmem:kmem_cache_alloc"))
        self.assertIn("req != g_task_size", leak)
        self.assertIn("[task] candidates=%d", leak)
        main = src[src.index("int main(int argc, char **argv)"):]
        self.assertIn("[cred] channel ok uid=%u euid=%u", main)
        self.assertIn("g_tasks[(attempt - 1) % g_ntasks]", main)


    def test_h1c_reclaim_requires_whole_slab_self_allocation(self) -> None:
        src = (ROOT / "binary-sources/98260-h1c/uaf_plant.c").read_text(
            encoding="utf-8")
        self.assertIn("static int trace_alloc_covers_self(uint64_t base)", src)
        covers = function_body(src, "trace_alloc_covers_self")
        self.assertIn("pfn_in_line(line, base)", covers)
        self.assertIn("pfn_in_line(line, base + 1)", covers)
        self.assertIn("cov == 3", covers)
        reclaim = function_body(src, "reclaim_stream")
        self.assertIn("trace_alloc_covers_self(base)", reclaim)
        self.assertNotIn('trace_seen_self("mm_page_alloc:"', reclaim)
        self.assertIn("sock = (sock + 1) % g_nstream;", reclaim)
        one = function_body(src, "one_uaf")
        self.assertIn("trace_clear();", one)
        self.assertLess(one.index("trace_clear();"), one.index("phase, 4"))
        self.assertIn("static void trace_clear(void)", src)


    def test_manager_install_is_not_gated_on_module_live(self) -> None:
        # A live LKM is not a registered userspace.  The post-load
        # `ksud install` used to be skipped whenever .ksu_loaded existed, so a
        # module-live-but-late-load-failed run ended with no su provider and a
        # cleaned workdir (the export log's SU_REPAIR failure).
        run = self.runner
        start = run.index("# Upstream-style manager userspace setup after handoff")
        end = run.index('if [ "$KSU_SU_READY" = "1" ]; then', start)
        block = run[start:end]
        self.assertNotIn('[ ! -f "$D/.ksu_loaded" ]', block)
        self.assertIn('if [ "$KSU_SU_READY" != "1" ]', block)
        self.assertIn('for _ms in "$SU" /system/bin/su su /data/adb/ksu/bin/su',
                      block)
        self.assertIn("98260_KSUD_LATELOAD_POST_RC=", block)
        self.assertIn("98260_SU_PROVIDER_POST=", block)
        src = (ROOT / "main/compose-app/app/src/main/java/com/aoki/magicroot/MainActivity.java").read_text(encoding="utf-8")
        self.assertIn("boolean ksuSuReady", src)
        self.assertIn("ksuLoaded && !ksuSuReady", src)


    def test_h1c_runner_extends_while_plant_progresses(self) -> None:
        run = (ROOT / "main/app/assets/98260-h1c/run_h1c.sh").read_text(
            encoding="utf-8")
        self.assertIn("ROOTD_HARD=${H1C_ROOTD_HARD:-900}", run)
        self.assertIn("ROOTD_IDLE_MAX=${H1C_ROOTD_IDLE_MAX:-120}", run)
        self.assertIn("98260_H1C_PROGRESS", run)
        self.assertIn("98260_H1C_WAIT_EXTEND", run)
        self.assertIn("plant still running after ${SECONDS}s", run)
        self.assertIn('while [ "$SECONDS" -lt "$ROOTD_HARD" ]', run)
        self.assertIn("_p_sig=\"${_p_attempts}/${_p_hits}\"", run)


    def test_h1c_dynamic_flag_is_initialized_before_first_read(self) -> None:
        # Fixed 117 used to abort under set -u before H1C_DYNAMIC_LOCAL was
        # assigned.  The exact-profile override must precede the adaptive-syms
        # check so stale adaptive state cannot leak into a built-in profile.
        run = self.runner
        assignment = run.index('H1C_DYNAMIC_LOCAL="${MAGICROOT_98260_ADAPTIVE:-0}"')
        override = run.index("61821|61821brm|61821h1c117) H1C_DYNAMIC_LOCAL=0")
        first_read = run.index('if [ "$H1C_DYNAMIC_LOCAL" = "1" ]')
        self.assertLess(assignment, override)
        self.assertLess(override, first_read)
        self.assertEqual(run.count(
            'H1C_DYNAMIC_LOCAL="${MAGICROOT_98260_ADAPTIVE:-0}"'), 1)


    def test_rootd_chown_failure_has_socket_permission_fallback(self) -> None:
        rootd = (ROOT / "binary-sources/98260-6.12/rootd.c").read_text(encoding="utf-8")
        self.assertIn("chown denied", rootd)
        self.assertIn("chmod(path, 0666)", rootd)
        self.assertIn("peer.uid == 0 || peer.uid == 2000", rootd)


    def test_shizuku_tmpdir_remains_available_for_heredoc_helpers(self) -> None:
        src = (ROOT / "main/compose-app/app/src/main/java/com/aoki/magicroot/MainActivity.java").read_text(encoding="utf-8")
        self.assertIn('"HOME=/", "TMPDIR=/data/local/tmp"', src)


    def test_fake_cred_never_frees_installed_page_after_reap(self) -> None:
        src = SOURCE.read_text(encoding="utf-8")
        one = function_body(src, "one_uaf")
        self.assertIn("if (!g_no_real_cred)", one)
        self.assertIn("fake-cred is DIFFERENT", one)
        self.assertLess(one.index("fake-cred is DIFFERENT"), one.index("enforce after reap"))


    def test_fake_cred_rejects_tile_and_blob_overlap(self) -> None:
        src = SOURCE.read_text(encoding="utf-8")
        pick = function_body(src, "pick_triple")
        self.assertIn("skip fake-cred overlap", pick)
        self.assertIn("cred_hi", pick)
        self.assertIn("0x1f20", pick)


    def test_success_path_does_not_start_another_victim_sweep(self) -> None:
        src = SOURCE.read_text(encoding="utf-8")
        self.assertIn("if (!rooted)\n\t\tvictim_sweep();", src)
        finish = function_body(src, "victim_finish_or_watch")
        self.assertNotIn("victim_sweep();", finish)


    def test_fake_success_also_skips_post_success_sweep(self) -> None:
        src = SOURCE.read_text(encoding="utf-8")
        fake = src.split("if (g_no_real_cred) {", 1)[1].split(
            '[mode] real-cred', 1)[0]
        self.assertIn("if (!rooted)\n\t\t\tvictim_sweep();", fake)
        self.assertIn("Never sweep after a successful fake plant", fake)


    def test_fake_takeover_skips_setuid_over_forged_cred(self) -> None:
        src = SOURCE.read_text(encoding="utf-8")
        takeover = function_body(src, "mintwait_main")
        self.assertIn("takeover uid=", takeover)
        self.assertIn("if (geteuid() != 0 || getuid() != 0)", takeover)
        self.assertLess(takeover.index("takeover uid="), takeover.index("SYS_setuid"))


    def test_fake_lateload_retries_and_reports_ksu_log(self) -> None:
        run = (ROOT / "main/app/assets/98260/run98260.sh").read_text(encoding="utf-8")
        self.assertEqual(run.count("98260_FAKE_LATELOAD_RETRY=1"), 2)
        self.assertIn("KSU_LOG_TAIL=", run)
        self.assertGreaterEqual(run.count("KSU_LOG_TAIL="), 2)


    def test_fake_lateload_tries_working_su_providers(self) -> None:
        run = (ROOT / "main/app/assets/98260/run98260.sh").read_text(encoding="utf-8")
        self.assertIn("run_fake_late_load()", run)
        self.assertIn("/system/bin/su su /data/adb/ksu/bin/su", run)
        self.assertIn("98260_FAKE_LATELOAD_SU=", run)
        self.assertEqual(run.count("run_fake_late_load\n"), 4)

    def test_fake_registration_succeeds_on_module_live_not_userspace_rc(self) -> None:
        # The userspace late-load stage cannot reconnect to rootd after the
        # KSU module goes live (EACCES), but the module itself is loaded and
        # the manager reads that state.  Registration must therefore key on
        # ksu_loaded_98260, not on the late-load rc.
        run = (ROOT / "main/app/assets/98260/run98260.sh").read_text(encoding="utf-8")
        fake_load = run.index('elif [ "$CRED_MODE" = "fake" ]; then',
                              run.index('if [ "$KSU_ENABLE" = "1" ]'))
        real_load = run.index('elif [ -z "$SLIDE" ]', fake_load)
        fake_block = run[fake_load:real_load]
        self.assertNotIn('if [ "$_fake_ll_rc" = "0" ] && ksu_loaded_98260', fake_block)
        self.assertEqual(fake_block.count("98260_KSU_USERSLATE_RC="), 2)
        self.assertEqual(fake_block.count(
            "98260_KSU_USERSLATE_WARN=module_live_userspace_failed"), 2)
        self.assertEqual(fake_block.count('finish_ksu_loaded "$KSU_METHOD" 0'), 2)

    def test_6157_manager_ko_test_path_and_tables(self) -> None:
        run6157 = (ROOT / "main/app/assets/98260/run6157_full.sh").read_text(
            encoding="utf-8")
        self.assertIn("try_manager_ko_6157()", run6157)
        self.assertIn("try_manager_ko_6157; then", run6157)
        self.assertIn("98260_KSU_MANAGER_KO=begin", run6157)
        self.assertIn("98260_KSU_MANAGER_KO_PATCH", run6157)
        self.assertIn("98260_KSU_MANAGER_KO=failed", run6157)
        self.assertIn("98260_KSU_MANAGER_KO=patch_failed", run6157)
        self.assertIn("manager-ko-patched", run6157)
        self.assertIn("fallback=cga_or_m6", run6157)
        self.assertIn("MAGICROOT_6157_MANAGER_KO_LOAD", run6157)
        self.assertIn("syms-$_mgr_build.txt", run6157)
        self.assertIn("98260_KSU_MANAGER_KO_SYMS=runtime", run6157)
        self.assertIn("syms-manager-runtime.txt", run6157)
        self.assertIn("_mgr_syms_use", run6157)
        self.assertIn('"$_mgr_syms_use" "$_mgr_slide_use"', run6157)
        self.assertIn('ko_patch" "$MANAGER_KO"', run6157)
        self.assertIn("MAGICROOT_6157_MANAGER_KO_ALLOW_CGA_SYMS", run6157)
        self.assertIn("98260_KSU_MANAGER_KO=skip reason=kallsyms_unavailable",
                      run6157)
        self.assertIn("fallback_cga warn=stale_base_risk", run6157)
        # Hidden vendor symbols (g8d6 commit_creds) are filled from the
        # per-build CGA table in a second pass over the runtime-patched module.
        self.assertIn("98260_KSU_MANAGER_KO_CGA_FILL", run6157)
        run98260 = (ROOT / "main/app/assets/98260/run98260.sh").read_text(
            encoding="utf-8")
        # A failed --check slide is recovered from the exploit's own log; a
        # requested-but-not-loaded KSU can never be reported as success.
        self.assertIn("98260_SLIDE_SOURCE=payload_log", run98260)
        self.assertIn("98260_KSU=failed reason=not_loaded", run98260)
        self.assertIn("98260_CHAIN_END=ROOT_OK_KSU_FAIL code=82", run98260)
        profiles = (ROOT / "main/app/assets/kernel_profiles.sh").read_text(
            encoding="utf-8")
        self.assertIn('if [ "$profile" = "6157" ]', profiles)
        self.assertIn('KO_COMPAT="dynamic-6.1-manager-ko"', profiles)
        # The app must treat the 6.1 kernel's SU_PROVIDER=ready as a ready su,
        # not as "KSU loaded but su missing".
        self.assertIn('fullLog.contains("98260_SU_PROVIDER=ready")',
                      self.controller)
        # The manager-KO attempt must be an elif before the M6/CGA fallbacks.
        manager = run6157.index("try_manager_ko_6157; then")
        m6 = run6157.index('elif [ "$PROFILE_LOCAL" = "6157" ] && [ "$G7D" = "1" ]')
        self.assertLess(manager, m6)
        for build in ("g264", "gaaa", "g3306", "g84", "g77f", "g7d",
                      "gce849", "g5859", "g54d", "g40b1", "g8a496",
                      "g2e1f", "ge9da", "g8d6"):
            path = ROOT / f"main/app/assets/g264/syms-{build}.txt"
            self.assertTrue(path.is_file(), path)
            text = path.read_text(encoding="utf-8")
            self.assertIn("commit_creds 0x", text)
            self.assertIn("prepare_creds 0x", text)
        integrity = (ROOT / "main/app/assets/6157-integrity.tsv").read_text(
            encoding="utf-8")
        self.assertIn("\tg264/syms-g3306.txt\t", integrity)
        self.assertIn("\tg264/syms-g7d.txt\t", integrity)
        # The runner's per-profile row expectation must match the manifest.
        self.assertIn("6157) _want=23 ;;", run6157)
        self.assertIn("g264) _want=14 ;;", run6157)
        self.assertIn("*) _want=11 ;;", run6157)


if __name__ == "__main__":
    unittest.main(verbosity=2)
