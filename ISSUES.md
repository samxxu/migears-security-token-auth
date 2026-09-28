# migears-security-token-auth — Known Issues

> Summary of this module's issues. The items themselves are in [`issues/`](issues/README.md), one file
> per item: a front-matter header and a thread. This file is generated from them and can be rewritten at
> any time; edit an item, never this file.
>
> From the miGears Full-Module Code Review Report (5th round, 2026-09-28).

| | |
|---|---|
| Status | **Best state** |
| Size | src 363 lines (net) · 77 tests · 5 src files |

Legend — **P0** functional or security · **P1** documentation that fails when copied · **P2** robustness · **P3** metadata and docs

## At a glance

| | |
|---|---|
| Unsettled | P0 0 · P1 0 · P2 1 · P3 3 · other 1 |
| Settled | 3 of 8 |
| Waiting on the owner | `P2-2`, `P3-2`, `P3-3` |
| Waiting on the reviewer | `P3-1`, `G2` |
| Waiting on the coordinator | _nothing_ |
| Deferred, owing nobody | _nothing_ |

| id | level | status | title |
|---|---|---|---|
| [`P1-1`](issues/P1-1.md) | P1 | **verified** | The same root cause contradicts three documents: the README storage … |
| [`P1-2`](issues/P1-2.md) | P1 | **verified** | The `__migears_usr_` generation key is written only on the first … |
| [`P2-1`](issues/P2-1.md) | P2 | **verified** | `handleReuse()` ignores the return value of deleting the family marker, … |
| [`P2-2`](issues/P2-2.md) | P2 | **open** | `revoke()` through an expired access token silently no-ops. The access … |
| [`P3-1`](issues/P3-1.md) | P3 | **fixed** | Two README claims are stronger than the code: 'the two share nothing … |
| [`P3-2`](issues/P3-2.md) | P3 | **open** | A replay seen after the server clock moved backwards is classified as a … |
| [`P3-3`](issues/P3-3.md) | P3 | **open** | `deviceId` is stored verbatim, CR and LF included. Harmless here … |
| [`G2`](issues/G2.md) | - | **fixed** | Strict flags: `phpunit.xml.dist` currently sets `failOnWarning`, … |

## Unclosed

What is left to do here: every item whose `status` is not `verified` or `closed`,
highest severity first. `waiting on` is the party who acts next, read from that status.

| | |
|---|---|
| Unclosed | **5** of 8 |
| By status | `open` 3 · `fixed` 2 |
| Waiting on | owner 3 · reviewer 2 |

| level | item | status | waiting on | title |
|---|---|---|---|---|
| **P2** | [`P2-2`](issues/P2-2.md) | `open` | owner | `revoke()` through an expired access token silently no-ops. The access … |
| **P3** | [`P3-1`](issues/P3-1.md) | `fixed` | reviewer | Two README claims are stronger than the code: 'the two share nothing … |
| **P3** | [`P3-2`](issues/P3-2.md) | `open` | owner | A replay seen after the server clock moved backwards is classified as a … |
| **P3** | [`P3-3`](issues/P3-3.md) | `open` | owner | `deviceId` is stored verbatim, CR and LF included. Harmless here … |
| **-** | [`G2`](issues/G2.md) | `fixed` | reviewer | Strict flags: `phpunit.xml.dist` currently sets `failOnWarning`, … |

## Verdict

A well-designed token-based authentication system with refresh-token rotation, replay detection, and clear key separation. All functional and documentation-defect items from last round are resolved.

## Fixed since the last round

All prior P1/P2 items confirmed fixed: P1-1 generation key now renews on every login; P1-2 README lifetime claim corrected; P2-1 replay-detection storage failure now surfaces as storageFailure; G2 strict flags complete.

## Test gaps

No test for concurrent refresh attempts (race condition on token rotation); no test for token storage that throws an exception during check; no test for very long TTL values (integer overflow risk in 32-bit environments).

## Verification protocol

- `./vendor/bin/phpunit` · `composer analyse` · `composer validate`
- Warning/notice/deprecation/risky flags in `phpunit.xml.dist`: all four on
- A PHP warning counts as a test failure only where those flags are on; otherwise run `./vendor/bin/phpunit --fail-on-warning` explicitly.


---

# migears-security-token-auth — 已知问题

> 本模块问题的概览。条目本体在 [`issues/`](issues/README.md)，一条目一文件：前置字段加讨论串。
> 本文件由条目生成，随时可以整段重写；请改条目，不要改本文件。
>
> 出自 miGears 全模块代码评审报告（5th round，2026-09-28）。

| | |
|---|---|
| 状态 | **状态最好** |
| 体量 | src 363 行（净）· 77 个用例 · 5 个源文件 |

级别说明 — **P0** 功能性或安全级 · **P1** 文档照抄即错 · **P2** 健壮性 · **P3** 元数据与文档

## 状态一览

| | |
|---|---|
| 未了结 | P0 0 · P1 0 · P2 1 · P3 3 · 其他 1 |
| 已了结 | 3 / 8 |
| 等负责人 | `P2-2`, `P3-2`, `P3-3` |
| 等评审方 | `P3-1`, `G2` |
| 等协调人 | _无_ |
| 已暂缓，不欠谁 | _无_ |

| id | 级别 | 状态 | 标题 |
|---|---|---|---|
| [`P1-1`](issues/P1-1.md) | P1 | **verified** | 同一根因与三处文档矛盾：README 的存储表称 __migears_usr_ 是「自最近一次登录或撤销起 refresh TTL」，类 … |
| [`P1-2`](issues/P1-2.md) | P1 | **verified** | __migears_usr_ 代次键只在第一次 issue() 写入、之后不再写回（为避开与 revokeAllForUser() … |
| [`P2-1`](issues/P2-1.md) | P2 | **verified** | handleReuse() 忽略删除族标记的返回值，因此拒绝删除的存储后端会让重放撤销静默失效——而同样的失败在 revoke() 里是会抛 … |
| [`P2-2`](issues/P2-2.md) | P2 | **open** | 用已过期的 access token 调 `revoke()` 会静默 no-op。access 记录只活 `accessTtl`（15 … |
| [`P3-1`](issues/P3-1.md) | P3 | **fixed** | 两处 README 表述强于实现：「两者除了你的用户查询外不共享任何东西」（本包 require 并复用了 … |
| [`P3-2`](issues/P3-2.md) | P3 | **open** | 服务器时钟回拨后见到的重放被判为「重试」、保留族，而非盗用。令牌本身仍被拒，属 … |
| [`P3-3`](issues/P3-3.md) | P3 | **open** | `deviceId` 原样存储，含 CR 与 … |
| [`G2`](issues/G2.md) | - | **fixed** | 严格开关：`phpunit.xml.dist` 目前已开启 … |

## 未关闭

本模块还剩什么要做：所有 `status` 不是 `verified` 或 `closed` 的条目，按严重度从高到低。
`waiting on` 是下一步该动手的一方，由其状态读出。

| | |
|---|---|
| 未关闭 | **5** / 8 |
| 按状态 | `open` 3 · `fixed` 2 |
| 等在谁 | 负责人 3 · 评审方 2 |

| 级别 | 条目 | 状态 | 等在谁 | 标题 |
|---|---|---|---|---|
| **P2** | [`P2-2`](issues/P2-2.md) | `open` | 负责人 | 用已过期的 access token 调 `revoke()` 会静默 no-op。access 记录只活 `accessTtl`（15 … |
| **P3** | [`P3-1`](issues/P3-1.md) | `fixed` | 评审方 | 两处 README 表述强于实现：「两者除了你的用户查询外不共享任何东西」（本包 require 并复用了 … |
| **P3** | [`P3-2`](issues/P3-2.md) | `open` | 负责人 | 服务器时钟回拨后见到的重放被判为「重试」、保留族，而非盗用。令牌本身仍被拒，属 … |
| **P3** | [`P3-3`](issues/P3-3.md) | `open` | 负责人 | `deviceId` 原样存储，含 CR 与 … |
| **-** | [`G2`](issues/G2.md) | `fixed` | 评审方 | 严格开关：`phpunit.xml.dist` 目前已开启 … |

## 结论

一个设计精良的令牌认证系统，含刷新令牌轮换、重放检测、清晰的密钥分离。上一轮所有功能性与文档缺陷类问题均已解决。

## 本轮已修复确认

All prior P1/P2 items confirmed fixed: P1-1 generation key now renews on every login; P1-2 README lifetime claim corrected; P2-1 replay-detection storage failure now surfaces as storageFailure; G2 strict flags complete.

## 测试盲区

无并发刷新尝试测试（令牌轮换竞态条件）；无 check 期间令牌存储抛出异常的测试；无超长 TTL 值测试（32 位环境中的整数溢出风险）。

## 验证方式

- `./vendor/bin/phpunit` · `composer analyse` · `composer validate`
- `phpunit.xml.dist` 中的 warning/notice/deprecation/risky 开关：四个全开
- 只有在上述开关打开时 PHP 警告才会导致套件失败；否则请显式加 `--fail-on-warning`。
