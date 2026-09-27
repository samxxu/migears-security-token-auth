# migears-security-token-auth

Bearer token authentication for native apps and other non-browser clients: short-lived opaque
access tokens, single-use rotating refresh tokens, replay detection, and hashed-only storage.

It is the second authentication channel next to `migears-security`'s browser session
implementation (`MiAuth`). The two share nothing but your own user lookup.

**On the name.** The `security-` prefix marks this package as a submodule of `migears/security`: that
is the only package it requires, and it exists because the browser-shaped session there cannot serve
native clients. Modules without a single such upstream keep the flat `migears-<thing>` name.

## Why a separate module

`MiAuth` is browser-shaped end to end: a `PHPSESSID` cookie, a remember-me cookie protected by the
browser's `HttpOnly` / `Secure` / `SameSite` rules, and a same-origin login form. A native app has
none of that — no cookie jar, no same-origin boundary — and a long-lived remember-me value is
effectively a replayable bearer credential. Rather than growing a second mode inside `MiAuth`, token
authentication lives here, in its own class.

A full design write-up with diagrams is in
[`docs/token-auth-design/token-auth-design.html`](docs/token-auth-design/token-auth-design.html).

## Requirements

- PHP 8.1+
- [`migears/security`](https://github.com/samxxu/migears-security) ^2.0 (for `Token` and `SecurityException`)
- [`psr/simple-cache`](https://www.php-fig.org/psr/psr-16/) ^3.0 (the store is any PSR-16 cache)

## Installation

```bash
composer require migears/security-token-auth
```

For local development against the sibling checkout, `composer.json` already declares a `path`
repository pointing at `../migears-security`.

## Quick start

```php
use MiGears\SecurityTokenAuth\TokenAuth;

$auth = new TokenAuth(
    store: $cache,                         // any PSR-16 cache (see Storage below)
    userLoader: fn(string $id): ?object => $users->find($id),
    accessTtl: 900,                        // 15 minutes
    refreshTtl: 2592000,                   // 30 days
    reuseGracePeriod: 30,                  // seconds
);
```

```php
// Login endpoint — the identity source is your business, the module only issues
$pair = $auth->issue($user, deviceId: 'iphone-15');
return json_encode($pair->toArray());
// {"token_type":"Bearer","access_token":"…","expires_in":900,"refresh_token":"…"}

// Protected endpoint
$user = $auth->authenticate($bearer);      // null for unknown, expired, or wrong-type tokens
if ($user === null) { /* 401 */ }

// Refresh endpoint — rotates the refresh token and detects replay
$pair = $auth->refresh($refreshToken);

// Logout
$auth->revoke($refreshToken);              // revokes the whole rotation family

// Password change / "sign out everywhere"
$auth->revokeAllForUser($userId);
```

## What it does

| Concern | Behaviour |
|---|---|
| Token kind | Two tokens per login: a short-lived `access` and a long-lived `refresh` |
| Storage | Any PSR-16 cache; only a 32-hex prefix of `sha256(token)` is ever used as a key |
| Rotation | Every refresh consumes the presented refresh token and issues a new pair |
| Replay | A consumed token appearing again is rejected; after the grace window the whole family is revoked |
| Revocation | `revoke()` drops one family marker, `revokeAllForUser()` bumps the user generation; neither has to enumerate records |
| Lifetime | A family lives `refreshTtl` from its login; rotation never extends it |
| Verification | `authenticate()` returns the user or `null`, so middleware never branches on exceptions |
| Exceptions | `TokenAuthException` extends `SecurityException`, so existing catch blocks keep working |

## Storage

The store is any [PSR-16](https://www.php-fig.org/psr/psr-16/) cache: `migears/cache`, a Redis or APCu
adapter, a database-backed one. The module owns three key prefixes inside it and never enumerates
them:

| Key | Holds | Lifetime |
|---|---|---|
| `__migears_tok_` + 32 hex of `sha256(token)` | one token record: `type`, `user_id`, `family_id`, `expires_at`, `device_id`, `used_at` | access TTL for an access record, refresh TTL for a refresh record |
| `__migears_fam_` + 32 hex of `sha256(family_id)` | the generation the rotation family was issued under | refresh TTL, never extended |
| `__migears_usr_` + 32 hex of `sha256(user_id)` | the user's current generation | refresh TTL from the last login or revocation |

The hash is shortened because PSR-16 only guarantees keys up to 64 characters and a SHA-256 digest is
already 64. `TokenAuth::recordKey()`, `familyKey()` and `userKey()` are the authoritative way to
compute all three, which is what an operator needs to inspect or clear them.

Two consequences of resting on PSR-16 are worth stating plainly.

**The backend must be durable and must not evict.** Revocation is a key write, not a delete of every
record of a family, because PSR-16 cannot enumerate keys. A missing key counts as a mismatch, so a
store that drops keys under memory pressure logs users out instead of resurrecting revoked tokens,
which is the safe direction but still an outage. Run Redis with `noeviction` or use a
database-backed adapter, and treat this store as a system of record rather than a cache. This is the
one thing PSR-16 cannot express, so it is a documented requirement rather than a type.

**Expiry is the store's job.** Every record is written with a TTL, so an expired token reads as an
unknown one. The module's own `expires_at` check only matters for adapters that ignore or round up
TTLs. Consumed refresh records are deliberately left in place until they expire, because deleting
them would make a replay indistinguishable from a random guess; no cleanup job is needed any more.

Each protected request costs two round trips, a `get` for the record followed by a `getMultiple` for
the family and user keys. A rotation costs three writes: the consumed record plus the successor pair.

## Design decisions

- **PSR-16 instead of a store interface of its own.** The browser channel's rotation lives on a
  PSR-16 store too (`MiGears\Security\RememberMe`), so one cache adapter now serves both, and nobody
  has to write a store class to get started. The price is that PSR-16 cannot enumerate keys, which is
  why revocation rewrites a generation marker and why the backend has to be non-evicting.
- **Opaque tokens, not JWT.** A JWT removes the per-request store lookup but cannot be revoked before
  it expires. Revocation wins here; `TokenPair::toArray()` still speaks the OAuth 2.0 token response,
  so a JWT layer can be swapped in behind your middleware.
- **A finite session, not a self-renewing one.** A rotation hands out a fresh refresh token, but the
  family marker keeps its original lifetime, so a session ends `refreshTtl` after it started.
- **A grace window on replay.** Mobile clients legitimately retry a refresh when a response is lost.
  Inside `reuseGracePeriod` seconds a replayed token answers "already used" and keeps the family;
  outside it, the family is revoked. Set `reuseGracePeriod: 0` for strict behaviour.
- **Single use is not a hard concurrency guarantee.** PSR-16 has no compare-and-swap, so two requests
  racing on the same refresh token can both read it as unused and both receive a successor.
- **No `AuthInterface` implementation.** `login()` there returns `void` and its `$remember` flag is a
  cookie concept, so a bearer implementation could only satisfy the interface by ignoring both.
  Issuance is `issue()` / `refresh()`; the read side is `authenticate()`.

## Testing

```bash
composer test      # PHPUnit
composer analyse   # PHPStan, level 6
```

## License

MIT

---

# migears-security-token-auth（中文）

面向原生 App 及其他非浏览器客户端的 Bearer 令牌认证：短期不透明 access token、一次性轮换的
refresh token、重放检测，以及只存哈希的服务端存储。

它是 `migears-security` 浏览器会话实现（`MiAuth`）之外的第二条认证通道。两者除“你自己的用户查询”
外没有任何共享。

**关于名字。** `security-` 前缀表示它是 `migears/security` 的子模块：后者是它唯一的依赖，而它存在的
理由正是那个包里的浏览器形态会话无法服务原生客户端。没有这种唯一上游的模块，仍用扁平的
`migears-<名字>`。

## 为什么要独立成模块

`MiAuth` 从头到尾都是浏览器形态：`PHPSESSID` Cookie、靠浏览器 `HttpOnly` / `Secure` / `SameSite`
规则保护的 remember-me Cookie，以及同源提交的登录表单。原生 App 上这些都不存在——没有 Cookie 罐，
没有同源边界——而长期有效的 remember-me 值本质上就是可重放的 Bearer 凭证。与其在 `MiAuth` 里长出
第二个模式，不如把令牌认证独立到这里。

带图表的完整设计说明见
[`docs/token-auth-design/token-auth-design.html`](docs/token-auth-design/token-auth-design.html)。

## 环境要求

- PHP 8.1+
- [`migears/security`](https://github.com/samxxu/migears-security) ^2.0（用于 `Token` 与 `SecurityException`）
- [`psr/simple-cache`](https://www.php-fig.org/psr/psr-16/) ^3.0（存储即任意 PSR-16 缓存）

## 安装

```bash
composer require migears/security-token-auth
```

本地对着同级目录开发时，`composer.json` 已声明指向 `../migears-security` 的 `path` 仓库。

## 快速开始

```php
use MiGears\SecurityTokenAuth\TokenAuth;

$auth = new TokenAuth(
    store: $cache,                         // 任意 PSR-16 缓存（见下文“存储”）
    userLoader: fn(string $id): ?object => $users->find($id),
    accessTtl: 900,                        // 15 分钟
    refreshTtl: 2592000,                   // 30 天
    reuseGracePeriod: 30,                  // 秒
);
```

```php
// 登录端点——身份来源由业务决定，模块只负责签发
$pair = $auth->issue($user, deviceId: 'iphone-15');
return json_encode($pair->toArray());
// {"token_type":"Bearer","access_token":"…","expires_in":900,"refresh_token":"…"}

// 受保护端点
$user = $auth->authenticate($bearer);      // 未知 / 过期 / 类型不符 → null
if ($user === null) { /* 401 */ }

// 刷新端点——轮换 refresh token 并检测重放
$pair = $auth->refresh($refreshToken);

// 登出
$auth->revoke($refreshToken);              // 撤销整个轮换族

// 改密 / “登出所有设备”
$auth->revokeAllForUser($userId);
```

## 行为一览

| 关注点 | 行为 |
|---|---|
| 令牌种类 | 每次登录一对：短期 `access` 与长期 `refresh` |
| 存储 | 任意 PSR-16 缓存；键里只出现 `sha256(token)` 的前 32 位十六进制 |
| 轮换 | 每次刷新消费被出示的 refresh token，并签发新一对 |
| 重放 | 已消费令牌再次出现即拒绝；超出宽限期则撤销整个族 |
| 撤销 | `revoke()` 删除单个族标记，`revokeAllForUser()` 换一个新的用户代次；两者都不需要枚举记录 |
| 生命期 | 一个族自登录起只活 `refreshTtl`；轮换不会延长它 |
| 校验 | `authenticate()` 返回用户或 `null`，中间件无需处理异常分支 |
| 异常 | `TokenAuthException` 继承 `SecurityException`，既有 catch 块无需改动 |

## 存储

存储即任意 [PSR-16](https://www.php-fig.org/psr/psr-16/) 缓存：`migears/cache`、Redis 或 APCu 适配器、
数据库型适配器都可以。模块在缓存内占用三个键前缀，且从不枚举键：

| 键 | 内容 | 生命期 |
|---|---|---|
| `__migears_tok_` + `sha256(token)` 前 32 位十六进制 | 一条令牌记录：`type`、`user_id`、`family_id`、`expires_at`、`device_id`、`used_at` | access 记录为 access TTL，refresh 记录为 refresh TTL |
| `__migears_fam_` + `sha256(family_id)` 前 32 位十六进制 | 该轮换族签发时所处的代次 | refresh TTL，永不被延长 |
| `__migears_usr_` + `sha256(user_id)` 前 32 位十六进制 | 该用户当前的代次 | 自最近一次登录或撤销起 refresh TTL |

哈希之所以截断，是因为 PSR-16 只保证支持 64 个字符以内的键，而 SHA-256 十六进制摘要本身就占满 64 位。
`TokenAuth::recordKey()`、`familyKey()`、`userKey()` 是计算这三个键的权威方式，运维排查或清理时用它即可。

依赖 PSR-16 带来两条必须说清的后果。

**后端必须持久，且不能淘汰键。** 撤销是一次键写入，而不是删除某个族的全部记录，因为 PSR-16 无法枚举键。
缺失的键一律按“不匹配”处理，因此会淘汰键的存储只会把用户登出，而不会让已撤销的令牌复活：这是安全的方向，
但仍属故障。请把 Redis 配成 `noeviction`，或使用数据库型适配器，并把这里当作“记录源”而不是缓存。这是
PSR-16 唯一表达不了的东西，因此它被写成文档要求，而不是类型约束。

**过期由存储负责。** 每条记录都带 TTL 写入，因此过期令牌读起来等同于未知令牌。模块自身仍会检查
`expires_at`，但那只是给忽略或向上取整 TTL 的适配器兜底。已消费的 refresh 记录会被刻意保留至过期，
因为一旦删除，重放就与随机猜测无法区分；现在也不再需要清理任务。

每个受保护请求固定两次往返：先 `get` 取记录，再 `getMultiple` 取族标记与用户代次。一次轮换三次写入：
消费掉的旧记录，加上新的一对。

## 设计取舍

- **用 PSR-16 而不是自有存储接口。** 浏览器通道的轮换本来就跑在 PSR-16 上（`MiGears\Security\RememberMe`），
  现在一个缓存适配器可同时服务两条通道，接入时也不必先写一个存储类。代价是 PSR-16 无法枚举键，这正是撤销
  改为重写代次标记、以及后端必须不淘汰键的原因。
- **不透明令牌，而非 JWT。** JWT 能省掉每请求一次存储读取，但无法在过期前撤销。这里选择可撤销；
  `TokenPair::toArray()` 仍遵循 OAuth 2.0 令牌响应，因此可在中间件后面换成 JWT 实现。
- **会话不是自我续期，而是有上限。** 轮换会发出新的 refresh token，但族标记保持原有的生命期，因此一个
  会话自开始起 `refreshTtl` 后结束。
- **重放宽限期。** 移动端在响应丢失时确实会重试刷新。在 `reuseGracePeriod` 秒内，重放回答“已使用”
  并保留令牌族；超出则撤销令牌族。设 `reuseGracePeriod: 0` 即严格模式。
- **一次性不是强并发保证。** PSR-16 没有 compare-and-swap，两个请求同时出示同一个 refresh token 时，
  可能都读到“未使用”并各自拿到新令牌。
- **不实现 `AuthInterface`。** 其中 `login()` 返回 `void`，其 `$remember` 参数是 Cookie 概念，
  Bearer 实现只能靠忽略两者来满足接口。签发侧因此表达为 `issue()` / `refresh()`，读取侧为
  `authenticate()`。

## 测试

```bash
composer test      # PHPUnit
composer analyse   # PHPStan, level 6
```

## 许可

MIT
