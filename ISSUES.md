# migears-security-token-auth — Known Issues / 已知问题

> Summary of this module's issues. The items themselves are in [`issues/`](issues/README.md), one file
> per item: a front-matter header and a thread. This file is generated from them and can be rewritten at
> any time; edit an item, never this file.
>
> 本模块问题的概览。条目本体在 [`issues/`](issues/README.md)，一条目一文件：前置字段加讨论串。
> 本文件由条目生成，随时可以整段重写；请改条目，不要改本文件。
>
> From the miGears Full-Module Code Review Report (4th round, 2026-09-27).

| | |
|---|---|
| Status / 状态 | **P1 open / P1 待修** |
| Size / 体量 | src 821 lines (397 net) · 75 tests · 6 src files · first review this round |

Legend / 图例 — **P0** functional or security · **P1** documentation that fails when copied · **P2** robustness · **P3** metadata and docs
级别说明 — **P0** 功能性或安全级 · **P1** 文档照抄即错 · **P2** 健壮性 · **P3** 元数据与文档

## At a glance / 状态一览

| | |
|---|---|
| Items / 条目 | P0 0 · P1 2 · P2 1 · P3 1 · other 1 |
| Answered / 已回复 | 2 of 5 |
| Waiting / 等待回复 | `P1-1`, `P1-2`, `P2-1` |

| id | level | status | title |
|---|---|---|---|
| [`P1-1`](issues/P1-1.md) | P1 | **open** | The same root cause contradicts three documents: the README storage … |
| [`P1-2`](issues/P1-2.md) | P1 | **open** | The `__migears_usr_` generation key is written only on the first … |
| [`P2-1`](issues/P2-1.md) | P2 | **open** | `handleReuse()` ignores the return value of deleting the family marker, … |
| [`P3-1`](issues/P3-1.md) | P3 | **fixed** | Two README claims are stronger than the code: 'the two share nothing … |
| [`G2`](issues/G2.md) | - | **fixed** | Strict flags: `phpunit.xml.dist` currently sets `failOnWarning`, … |

## Verdict / 结论

A new module and one of the best-designed in the workspace: opaque tokens, single-use rotating refresh tokens with replay detection, hashed-only storage, PSR-16 as the only storage contract, and a README that explains every trade-off. One functional defect, reproduced: the user-generation key never refreshes its TTL, so later token families expire early and a new login silently logs out other devices.

新模块，也是全仓设计最讲究的之一：不透明令牌、一次性轮换 refresh、重放检测、只存哈希、以 PSR-16 作唯一存储契约，README 把每处取舍都讲清楚。但有一个已实证的功能缺陷：用户代次键的 TTL 从不刷新，导致后续令牌族提前失效，且新登录会静默登出其它设备。

## Fixed since the last round / 本轮已修复确认

新模块，无历史可比。 

## Test gaps / 测试盲区

No test advances the clock past the first login's user-key TTL — the existing second-login test only asserts "one write", which pins the defect as expected; no case for a failed family-key delete during replay handling; no concurrent-refresh case (accepted, PSR-16 has no CAS).

没有用例把时钟推过首次登录的用户键 TTL——现有的第二次登录用例只断言「写了一次」，等于把这个缺陷固化成了预期；无「重放处理时族标记删除失败」用例；无并发刷新用例（已接受，PSR-16 无 CAS）。

## Verification protocol / 验证方式

- `./vendor/bin/phpunit` · `composer analyse` · `composer validate`
- Warning/notice/deprecation/risky flags in `phpunit.xml.dist`: all four on
- A PHP warning counts as a test failure only where those flags are on; otherwise run `./vendor/bin/phpunit --fail-on-warning` explicitly.
- 只有在上述开关打开时 PHP 警告才会导致套件失败；否则请显式加 `--fail-on-warning`。
