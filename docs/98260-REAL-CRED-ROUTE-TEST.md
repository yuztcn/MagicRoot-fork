# 98260 — Teste da rota "real-cred" (upstream woshigenm/CVE-2026-98260)

Branch: `test/98260-real-cred-route`
Data do teste: 2026-11-09 (~00:36–01:05)
Dispositivo: HONOR MLY-AN00 · kernel `6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k`
Fonte analisada: <https://github.com/woshigenm/CVE-2026-98260> @ `d7830ab` + release `v1.4.5-app` + feed coolapk <https://www.coolapk1s.com/feed/74888861>

## 1. O que a rota nova faz de diferente

| Aspecto | Nossa rota atual (fake cred) | Rota upstream (real cred) |
|---|---|---|
| Cred | fake `struct cred` montada numa **página de spray** (skb/pipe) apontada por `task->cred` | escreve `0` em `cred+8` (uid/gid) da **cred real** da criança via `rb_erase` |
| `cred == real_cred` | quebrado (real_cred precisa de 2ª UAF para casar) | preservado nativamente |
| execve | proibido (`BUG_ON` + `security=NULL`) → precisa de **rootd residente** | permitido — `setuid(0)` + `execve` normais |
| Daemon | rootd PPID=1 **obrigatório** até reboot | nenhum daemon necessário |
| Página presa | a página do fake cred **nunca pode ser liberada** | nenhuma página fica presa após reap |
| KSU | via rootd + ksud | permissive + `cap_effective` + loader uid/gid → `finit_module` direto |

## 2. Resultados no dispositivo

Binário oficial extraído do APK `CVE98260Root.apk` v1.4.5-app (SHA-256
`5eef2534…3a0ab` — confere com o release notes). Executado como shell
(uid 2000) via `priv` em `/data/local/tmp/cveup`.

### Run 1 (00:40)

- plant 1: victim slab **nunca liberado** (30 s timeout) → zombie held
- plant 2: hit em 4 ms → write ok → `uid=0(root) u:r:shell:s0 ROOT_SHELL_OK`
- `g_held=1` → `park_forever`: keeper `mroot-keeper` (27179) + worker
  (27184) + zombie `yexec` (27189) + 10 zombies auxiliares ficaram vivos
- Reboot subsequente → `sys.resettype = abnormal:AP_S_PANIC`
  (mesmo mecanismo documentado em `docs/98260-PANIC-2026-11-07-ANALYSIS.md`:
  zombie armed cai no init e o reap executa `rb_erase` no nó stale)

### Run 2 (00:53, boot limpo)

- plant 1: hit em **1 ms** (pre-alloc order-2 por pid 17590), reap limpo
- `uid=0(root) u:r:shell:s0`, `setuid(0)=0`, resuid `0/0/2000` → `ROOT_SHELL_OK`
- `[+] done`, exit 0, **g_held=0**
- Verificação pós-run: `ps` varredura — **zero** magicroot/mroot/yexec;
  nenhum zombie residual; keeper e worker encerrados
- Reboot subsequente → `bootreason=reboot`, `resettype=others:UNKNOWN`
  → **reboot NORMAL, sem panic**

## 3. Veredito do A/B no mesmo hardware

| Execução | Resíduo | Reboot | Resultado |
|---|---|---|---|
| fake cred + zombie held (run 1) | keeper+worker+zombie armed | normal→init reap | **AP_S_PANIC** |
| real-cred, zero resíduo (run 2) | nenhum | normal | **OK, sem panic** |

## 4. O que isso responde à pergunta "melhora o soft-reboot?"

**Parcialmente — e é uma melhora real, mas não resolve sozinho.**

1. **O que melhora de verdade:** elimina duas das três condições que tornam
   nossa rota explosiva: (a) nenhuma página de cred fica pinada para sempre;
   (b) nenhum daemon precisa ficar vivo até o reboot. No caminho feliz o
   resíduo é **zero** — não há NADA para o init colher. Isso foi provado no
   hardware: reboot normal após sucesso.
2. **O que NÃO resolve:** a **condição raiz do panic continua intacta** —
   qualquer plant que erre deixa zombie armed, e o upstream apenas faz
   `park_forever`. O Run 1 demonstrou isso na prática: park → reboot →
   `AP_S_PANIC`, mesmo mecanismo do nosso histórico. Ou seja, a rota
   real-cred **não elimina** a bomba; só deixa de adicionar as suas próprias.
3. Conclusão: **migrar o write final para real-cred vale a pena**
   (remove rootd residente + página pinada + `real_cred` desencontrado), mas
   deve vir acompanhado do **nosso** gerenciamento de zombies — o trabalho
   já em curso em `fix/98260-zygote-lifecycle` (victim ledger + zero-page
   repair + watch) é ESTRITAMENTE SUPERIOR ao `park_forever` do upstream,
   que não tenta resolver nada.

## 5. Diferenças de implementação observadas (para o port)

- Plant no upstream: `run_plant(target, kind, tag)` com `PLANT_ZERO` /
  `PLANT_PTR` / `PLANT_SELINUX`; detecção de hit por `mm_page_alloc`
  cobrindo o pfn + gfp `0x5428c0`/`0x1d20c0`, validando `hit_spray` e
  `hit_off`. Semântica equivalente ao nosso stream, mas com `slide_low`
  e `det_ns` instrumentados.
- Criança do cred: `leak_cred` faz `fork` + `execve("/proc/self/exe", "wait")`
  para alocar cred real e lê o ponteiro via kmem trace (site low21
  `0x19c474`, req `0xb8`/alloc `0xc0`) — igual ao nosso `CRED_LINK`.
- Modo KSU (`CVE_KSU_MODE=1`): 3 plantes adicionais —
  `selinux_state-7=0`, `cred+0x40 cap_effective` (bit16), `cred+8 uid/gid` —
  depois `finit_module` com `allow_shell=1`. Mesma linha do nosso
  `root_stage.sh`, mas sem rootd.
- `lifecycle.h`: keeper com `PR_SET_CHILD_SUBREAPER`, `setsid`,
  ignore de SIGHUP/INT/TERM/PIPE, `mark_parked` grava `PARKED` com boot_id
  (o nosso estado ARMED cobre isso; o upstream não tem equivalente ao
  nosso ledger/repair).

## 6. Recomendação

1. **Portar a escrita final para real-cred** nos payloads 98260 (e a lógica
   de setuid/exec subsequente), mantendo nosso victim ledger — a combinação
   é estritamente melhor que qualquer um dos dois isolados.
2. Manter o `fix/98260-zygote-lifecycle` como linha principal de defesa do
   panic; a rota nova não o substitui.
3. Avaliar depois o port da cadeia KSU (`PLANT_SELINUX`+cap+uid) como
   alternativa ao rootd, reduzindo o tempo de vida de processo residente.
4. Registrar que reboot durante estado "parked" continua sendo
   `AP_S_PANIC` — nenhuma rota remove isso; só o nosso sweep/repair mitiga.

## 7. Artefatos

- Upstream repo local: `workspace/cve-98260-upstream`
- APK extraído: `workspace/upstream-apk-test/`
- Stage no device: `/data/local/tmp/cveup` (pode ser removido)
- Logs de run: saída do harness de teste (run 1 e run 2 reproduzidos acima)
