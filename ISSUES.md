# migears-security-token-auth — Known Issues

> Summary of this module's issues. The items themselves are in [`issues/`](issues/README.md), one file
> per item: a front-matter header and a thread. This file is generated from them and can be rewritten at
> any time; edit an item, never this file.
>
> From the miGears Full-Module Code Review Report (6th round, 2026-10-01).

| | |
|---|---|
| Status | **Best state** |
| Size | src 398 lines (net) · 79 tests · 6 src files |

Legend — **P0** functional or security · **P1** documentation that fails when copied · **P2** robustness · **P3** metadata and docs

## At a glance

| | |
|---|---|
| Unsettled | P0 0 · P1 0 · P2 0 · P3 0 · other 0 |
| Settled | 8 of 8 |
| Waiting on the owner | _nothing_ |
| Waiting on the coordinator | _nothing_ |
| Waiting on the reviewer | _nothing_ |
| Deferred, owing nobody | _nothing_ |

| id | level | status | title |
|---|---|---|---|
| [`P1-1`](issues/P1-1.md) | P1 | **verified** | The same root cause contradicts three documents: the README storage … |
| [`P1-2`](issues/P1-2.md) | P1 | **verified** | The `__migears_usr_` generation key is written only on the first … |
| [`P2-1`](issues/P2-1.md) | P2 | **verified** | `handleReuse()` ignores the return value of deleting the family marker, … |
| [`P2-2`](issues/P2-2.md) | P2 | **verified** | `revoke()` through an expired access token silently no-ops. The access … |
| [`P3-1`](issues/P3-1.md) | P3 | **verified** | Two README claims are stronger than the code: 'the two share nothing … |
| [`P3-2`](issues/P3-2.md) | P3 | **verified** | A replay seen after the server clock moved backwards is classified as a … |
| [`P3-3`](issues/P3-3.md) | P3 | **verified** | `deviceId` is stored verbatim, CR and LF included. Harmless here … |
| [`G2`](issues/G2.md) | - | **verified** | Strict flags: `phpunit.xml.dist` currently sets `failOnWarning`, … |

## Unclosed

_Nothing unclosed — every item in this module is `verified` or `closed`._

## Verdict

The three promises now match the behaviour without a line of code moving, which is exactly what the ruling chose; the module can settle as verified.

## Fixed since the last round

P2-2, P3-2 and P3-3 verified: all three were documentation-direction fixes (the revoke() contract is scoped to live tokens, reuse detection is stated to assume a monotonic clock, deviceId is recorded as stored verbatim and never used in a key), in place with behaviour untouched.

## Test gaps

The whole suite runs against the InMemoryCache double; that double’s has() decides existence by comparing the value with its own class-name string, an uncovered boundary; and issue() writes the family marker before generating the pair, so a failed pair leaves an orphan family with no test.

## Verification protocol

- `./vendor/bin/phpunit` · `composer analyse` · `composer validate`
- Warning/notice/deprecation/risky flags in `phpunit.xml.dist`: all four on
- A PHP warning counts as a test failure only where those flags are on; otherwise run `./vendor/bin/phpunit --fail-on-warning` explicitly.


---

# migears-security-token-auth — 已知问题

> 本模块问题的概览。条目本体在 [`issues/`](issues/README.md)，一条目一文件：前置字段加讨论串。
> 本文件由条目生成，随时可以整段重写；请改条目，不要改本文件。
>
> 出自 miGears 全模块代码评审报告（6th round，2026-10-01）。

| | |
|---|---|
| 状态 | **状态最好** |
| 体量 | src 398 行（净）· 79 个用例 · 6 个源文件 |

级别说明 — **P0** 功能性或安全级 · **P1** 文档照抄即错 · **P2** 健壮性 · **P3** 元数据与文档

## 状态一览

| | |
|---|---|
| 未了结 | P0 0 · P1 0 · P2 0 · P3 0 · 其他 0 |
| 已了结 | 8 / 8 |
| 等模块主 | _无_ |
| 等协调人 | _无_ |
| 等评审方 | _无_ |
| 已暂缓，不欠谁 | _无_ |

| id | 级别 | 状态 | 标题 |
|---|---|---|---|
| [`P1-1`](issues/P1-1.md) | P1 | **verified** | 同一根因与三处文档矛盾：README 的存储表称 __migears_usr_ 是「自最近一次登录或撤销起 refresh TTL」，类 … |
| [`P1-2`](issues/P1-2.md) | P1 | **verified** | __migears_usr_ 代次键只在第一次 issue() 写入、之后不再写回（为避开与 revokeAllForUser() … |
| [`P2-1`](issues/P2-1.md) | P2 | **verified** | handleReuse() 忽略删除族标记的返回值，因此拒绝删除的存储后端会让重放撤销静默失效——而同样的失败在 revoke() 里是会抛 … |
| [`P2-2`](issues/P2-2.md) | P2 | **verified** | 用已过期的 access token 调 `revoke()` 会静默 no-op。access 记录只活 `accessTtl`（15 … |
| [`P3-1`](issues/P3-1.md) | P3 | **verified** | 两处 README 表述强于实现：「两者除了你的用户查询外不共享任何东西」（本包 require 并复用了 … |
| [`P3-2`](issues/P3-2.md) | P3 | **verified** | 服务器时钟回拨后见到的重放被判为「重试」、保留族，而非盗用。令牌本身仍被拒，属 … |
| [`P3-3`](issues/P3-3.md) | P3 | **verified** | `deviceId` 原样存储，含 CR 与 … |
| [`G2`](issues/G2.md) | - | **verified** | 严格开关：`phpunit.xml.dist` 目前已开启 … |

## 未关闭

_无未关闭条目——本模块每条都已是 `verified` 或 `closed`。_

## 结论

三条承诺现与行为相符，一行代码未动，正是裁定所选；本模块可按 verified 落定。

## 本轮已修复确认

P2-2, P3-2 and P3-3 verified: all three were documentation-direction fixes (the revoke() contract is scoped to live tokens, reuse detection is stated to assume a monotonic clock, deviceId is recorded as stored verbatim and never used in a key), in place with behaviour untouched.

## 测试盲区

全套只对测试替身 InMemoryCache 跑；该替身的 has() 用「值是否等于自身类名字符串」判存在，这条边界未覆盖；issue() 先写族标记再生成本对，成对写入失败会留下孤儿族标记，无用例。

## 验证方式

- `./vendor/bin/phpunit` · `composer analyse` · `composer validate`
- `phpunit.xml.dist` 中的 warning/notice/deprecation/risky 开关：四个全开
- 只有在上述开关打开时 PHP 警告才会导致套件失败；否则请显式加 `--fail-on-warning`。
