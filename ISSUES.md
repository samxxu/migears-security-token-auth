# migears-security-token-auth — Known Issues / 已知问题

> Generated from the miGears Full-Module Code Review Report (4th round, 2026-09-27).
> This file has two regions. Everything above **Owner feedback** is generated from the report — do
> not edit it there. The **Owner feedback** region belongs to the module maintainer: write into it,
> and it is preserved verbatim when the file is regenerated.
> A `fixed` reply is verified against the code by the reviewer before the finding is closed; a
> `rejected` reply is either accepted as a false positive or answered with counter-evidence.
>
> 本文件分两个区域。**「负责人反馈」之前的全部内容**由评审报告生成，请勿在该区修改；
> **「负责人反馈」区**归模块负责人所有，重新生成时会原样保留。
> 标注 `fixed`（已修复）的回复会被评审对照代码核实后才关闭；标注 `rejected`（不认同）的，
> 评审要么采纳为误报，要么给出反驳证据。
>
> 摘自 miGears 全模块代码评审报告（第四轮，2026-09-27）。

| | |
|---|---|
| Status / 状态 | **P1 open / P1 待修** |
| Findings / 问题 | P0 0 · P1 2 · P2 1 · P3 1 |
| Size / 体量 | src 821 lines (397 net) · 75 tests · 6 src files · first review this round |

Legend / 图例 — **P0** functional or security · **P1** documentation that fails when copied · **P2** robustness · **P3** metadata and docs
级别说明 — **P0** 功能性或安全级 · **P1** 文档照抄即错 · **P2** 健壮性 · **P3** 元数据与文档

## Verdict / 结论

A new module and one of the best-designed in the workspace: opaque tokens, single-use rotating refresh tokens with replay detection, hashed-only storage, PSR-16 as the only storage contract, and a README that explains every trade-off. One functional defect, reproduced: the user-generation key never refreshes its TTL, so later token families expire early and a new login silently logs out other devices.

新模块，也是全仓设计最讲究的之一：不透明令牌、一次性轮换 refresh、重放检测、只存哈希、以 PSR-16 作唯一存储契约，README 把每处取舍都讲清楚。但有一个已实证的功能缺陷：用户代次键的 TTL 从不刷新，导致后续令牌族提前失效，且新登录会静默登出其它设备。

## Fixed since the last round / 本轮已修复确认

新模块，无历史可比。 

## Open findings / 未修问题


### P1

**P1-1** — `README:96, docs/token-auth-design, src/TokenAuth.php:33-35`

- EN: The same root cause contradicts three documents: the README storage table says `__migears_usr_` lives "refresh TTL from the most recent login or revocation", the class docblock says "a family lives refreshTtl from its login", and the design document repeats it — none of which matches the implementation.
- 中文: 同一根因与三处文档矛盾：README 的存储表称 __migears_usr_ 是「自最近一次登录或撤销起 refresh TTL」，类 docblock 称「族自其登录起存活 refreshTtl」，设计文档同样重述——三者都与实现不符。
- Verification / 验证: reproduced / 已实证

**P1-2** — `src/TokenAuth.php:355-367,329-344,168-173`

- EN: The `__migears_usr_` generation key is written only on the first `issue()` and never rewritten (to avoid racing with `revokeAllForUser()`), so its TTL runs from the *first* login while each family marker's TTL runs from *its own* login. Reproduced with a controllable clock (refreshTtl 100, accessTtl 900): a family issued at t=90 still had 900s of access life but was refused at t=101; and a login at t=101 silently invalidated families A and B. Direction is fail-closed (no revival of revoked tokens), so this is a usability/functional defect rather than a hole.
- 中文: __migears_usr_ 代次键只在第一次 issue() 写入、之后不再写回（为避开与 revokeAllForUser() 的竞态），于是它的 TTL 从**首次**登录起算，而每个族标记的 TTL 从**自己那次**登录起算。用可控时钟实证（refreshTtl 100、accessTtl 900）：t=90 签发的族本应还有 900 秒访问寿命，却在 t=101 被拒；t=101 的一次登录静默作废了 A、B 两族。方向是 fail-closed（不会复活已吊销令牌），故属可用性/功能缺陷而非漏洞。
- Verification / 验证: reproduced / 已实证


### P2

**P2-1** — `src/TokenAuth.php:382 vs :230-232`

- EN: `handleReuse()` ignores the return value of deleting the family marker, so a storage backend that refuses deletes can leave replay revocation silently ineffective — while the same failure in `revoke()` does throw `storageFailure`.
- 中文: handleReuse() 忽略删除族标记的返回值，因此拒绝删除的存储后端会让重放撤销静默失效——而同样的失败在 revoke() 里是会抛 storageFailure 的。
- Verification / 验证: static / 仅静态推断


### P3

**P3-1** — `README:7,9-11,160-162 vs composer.json:17-21`

- EN: Two README claims are stronger than the code: "the two share nothing but your own user lookup" (this package requires and reuses `MiGears\Security\Token` and `SecurityException`) and "the only dependency" (it also requires `psr/simple-cache`, as its own Requirements section says).
- 中文: 两处 README 表述强于实现：「两者除了你的用户查询外不共享任何东西」（本包 require 并复用了 MiGears\Security\Token 与 SecurityException）与「唯一依赖」（它还 require psr/simple-cache，其自身的 Requirements 段也这么写）。
- Verification / 验证: static / 仅静态推断

## Test gaps / 测试盲区

No test advances the clock past the first login's user-key TTL — the existing second-login test only asserts "one write", which pins the defect as expected; no case for a failed family-key delete during replay handling; no concurrent-refresh case (accepted, PSR-16 has no CAS).

没有用例把时钟推过首次登录的用户键 TTL——现有的第二次登录用例只断言「写了一次」，等于把这个缺陷固化成了预期；无「重放处理时族标记删除失败」用例；无并发刷新用例（已接受，PSR-16 无 CAS）。

## Verification protocol / 验证方式

- `./vendor/bin/phpunit` · `composer analyse` · `composer validate`
- Warning/notice/deprecation/risky flags in `phpunit.xml.dist`: on: Warning, Risky
- A PHP warning counts as a test failure only where those flags are on; otherwise run `./vendor/bin/phpunit --fail-on-warning` explicitly.
- 只有在上述开关打开时 PHP 警告才会导致套件失败；否则请显式加 `--fail-on-warning`。

## Owner feedback / 负责人反馈

<!-- OWNER-FEEDBACK:BEGIN -->
<!-- 渠道说明 / channel notice — 跨模块协调人发布，长期有效 / issued by the cross-module coordinator, standing
     ISSUES.md 是本模块「完整」的问题讨论与修复渠道，不只是评审结论的存放处。
     ISSUES.md is this module's COMPLETE issue-discussion-and-fix channel, not merely where review verdicts land.

     1. 每位负责人只对自己模块负责。对别的模块有意见、疑问、反证或改动建议，写入「对方模块」的 ISSUES.md，
        不要写在自己模块里。
        Each owner is responsible for their own module only. Opinions, questions, counter-evidence and
        change requests about ANOTHER module go into THAT module's ISSUES.md, never into your own.
     2. 在对方模块的文件里注明你是谁：模块名 + 身份。署名是硬要求，不署名则无法追溯来源。
        Sign it in the other module's file: your module name and your role. Signing is mandatory; an
        unsigned entry cannot be traced back to its author.
     3. 署名格式 / signature forms, so the source is distinguishable:
          reviewer — migears-full-review   评审方
          coordinator — cross-module       跨模块协调人
          owner — migears-<module>         其他模块负责人
     4. 结论文本一律带状态词：accepted / fixed / rejected / deferred / question / new-evidence。
        无署名条目下一轮可能被按新发现重新评级。
        Sign conclusions with one status word: accepted / fixed / rejected / deferred / question /
        new-evidence. An unsigned entry may be re-graded as a new finding in the next round.
     5. 开工之前先通读本文件：把每条开启条目按证据评估（签名条目也算），再把你接受的条目与自己的工作一并执行，
        不要拆成两轮。每条都要有状态词。
        Read this file before starting work: evaluate every open item on its evidence, signed entries
        included, then execute the ones you accept together with your own work in one pass. Every item
        gets a status word. -->

<!-- Maintainers: reply under each finding's `### <id>` heading and keep the headings, so the
     reviewer can map your reply to the finding. Status vocabulary, one word followed by your
     reasoning and any evidence:
       accepted      you agree; it will be fixed
       fixed         you believe it is already fixed in the code (the reviewer verifies this)
       rejected      you disagree — give the reason; the reviewer either accepts it as a false
                     positive or answers with counter-evidence
       deferred      deliberate, out of scope for now — give the reason
       question      you need a decision or clarification first
       new-evidence  you have additional facts bearing on the finding
     You may also add findings of your own under `### New — <short title>`.

     负责人：请在对应 `### <编号>` 标题下逐条回复，并保留标题以便评审对应。
     状态词（一个词 + 理由与证据）：
       accepted      认同，将会修复
       fixed         认为代码里已经修好（评审会对照代码核实）
       rejected      不认同——请给理由；评审要么采纳为误报，要么给出反驳证据
       deferred      有意暂缓或超出范围——请给理由
       question      需要先明确或决策
       new-evidence  补充与本次结论相关的新事实
     也欢迎在 `### New — <简短标题>` 下补充你发现的问题。 -->

### P1-1
<!-- 负责人反馈 / owner response here -->

### P1-2
<!-- 负责人反馈 / owner response here -->

### P2-1
<!-- 负责人反馈 / owner response here -->

### P3-1
<!-- 负责人反馈 / owner response here -->

- **fixed** — both claims were indeed stronger than the code, and both are now corrected in the README.
  No code changed; the implementation was always right, the prose was not.
  - What the code says: `composer.json:17-21` requires **both** `psr/simple-cache: ^3.0` and
    `migears/security: ^2.0`; `src/TokenAuth.php:7` `use MiGears\Security\Token;` and
    `src/Exception/TokenAuthException.php:7` `use MiGears\Security\Exception\SecurityException;` — so the
    two packages do share more than the user lookup, and `migears/security` is not the only dependency.
  - README:7 now reads "Beyond the low-level `Token` and `SecurityException` helpers both use, the two
    share nothing but your own user lookup."
  - README:9-11 now reads "…that is the only **miGears** package it requires — its other runtime
    dependency is `psr/simple-cache` — …".
  - The Chinese half mirrors both at README:157-158 and README:160-162, so the two languages still agree.
  - The `## Requirements` list (README:24-28) already named both packages and is unchanged.
  - Commands / observed after the edit: `./vendor/bin/phpunit` → `OK (77 tests, 196 assertions)`, exit 0;
    `./vendor/bin/phpstan analyse --no-progress` → `[OK] No errors`, exit 0. `git diff --stat` → only
    `README.md` (10 insertions, 8 deletions). This is a documentation-only fix, so no new test applies.

  owner — migears-security-token-auth

<!-- 跨模块条目 / cross-module items — 由跨模块协调人提出，非本轮评审 finding。口径见工作区根目录 `migears-engineering-gates.md`。
      Filed by the cross-module coordinator, not by the round's review. Standard: `migears-engineering-gates.md` at the workspace root. -->

### G2

- EN: Strict flags: `phpunit.xml.dist` currently sets `failOnWarning`, `failOnRisky`, `beStrictAboutOutputDuringTests`. The standard is all five — `failOnWarning`, `failOnNotice`, `failOnDeprecation`, `failOnRisky`, `beStrictAboutOutputDuringTests` — which 11 of 27 modules set. Missing here: `failOnNotice`, `failOnDeprecation`. Turn them on and make the suite green; run `./vendor/bin/phpunit` and `composer analyse` before and after, and expect the first run to surface real warnings. If a flag genuinely cannot be turned on, reply `deferred` with the failing test and the reason instead of leaving the suite red.
- 中文: 严格开关：`phpunit.xml.dist` 目前已开启 `failOnWarning`、`failOnRisky`、`beStrictAboutOutputDuringTests`。标准是五个全开——`failOnWarning`、`failOnNotice`、`failOnDeprecation`、`failOnRisky`、`beStrictAboutOutputDuringTests`——27 个模块中 11 个如此。本模块缺 `failOnNotice`、`failOnDeprecation`。请打开并让套件保持全绿；改动前后各跑一次 `./vendor/bin/phpunit` 与 `composer analyse`，第一次跑出真警告是预期内的。若某个开关确实无法打开，请回复 `deferred` 并给出失败的用例与原因，而不是把套件留在红灯状态。
- Reply with one status word (`accepted` / `fixed` / `rejected` / `deferred` / `question`). / 请回复一个状态词（`accepted` / `fixed` / `rejected` / `deferred` / `question`）。
coordinator — cross-module

- **fixed** — all five strict flags are now on. `phpunit.xml.dist` previously set
  `failOnWarning`, `failOnRisky`, `beStrictAboutOutputDuringTests`; I added `failOnNotice` and
  `failOnDeprecation` and, matching the reference shape
  (`migears-data-structure/phpunit.xml.dist`), the three `displayDetailsOnTestsThatTrigger*`
  attributes. Every pre-existing attribute (`colors`, `cacheDirectory`, `executionOrder="random"`) and
  the `<testsuites>`/`<source>` structure were kept.
  - Before: `./vendor/bin/phpunit` → `OK (77 tests, 196 assertions)`, exit 0.
  - After: `./vendor/bin/phpunit` → `OK (77 tests, 196 assertions)`, exit 0 — no warning, notice,
    deprecation, risky test or stray output surfaced, so the two new flags cost nothing here.
  - `./vendor/bin/phpstan analyse --no-progress` → `[OK] No errors`, exit 0, before and after.
  - `phpunit.xml.dist:8-15` now sets `failOnWarning`, `failOnNotice`, `failOnDeprecation`,
    `failOnRisky`, `beStrictAboutOutputDuringTests`, `displayDetailsOnTestsThatTriggerWarnings`,
    `displayDetailsOnTestsThatTriggerNotices`, `displayDetailsOnTestsThatTriggerDeprecations`, all `true`.

  owner — migears-security-token-auth

<!-- OWNER-FEEDBACK:END -->
