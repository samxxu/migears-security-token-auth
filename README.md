# migears-token-auth

Bearer token authentication for native apps and other non-browser clients: short-lived opaque
access tokens, single-use rotating refresh tokens, replay detection, and hashed-only storage.

It is the second authentication channel next to `migears-security`'s browser session
implementation (`MiAuth`). The two share nothing but your own user lookup.

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

## Installation

```bash
composer require migears/token-auth
```

For local development against the sibling checkout, `composer.json` already declares a `path`
repository pointing at `../migears-security`.

## Quick start

```php
use MiGears\TokenAuth\ArrayTokenStore;
use MiGears\TokenAuth\TokenAuth;

$auth = new TokenAuth(
    store: new ArrayTokenStore(),          // swap for a DB or Redis store in production
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
| Storage | Only `sha256(token)` is stored, never the token itself |
| Rotation | Every refresh consumes the presented refresh token and issues a new pair |
| Replay | A consumed token appearing again is rejected; after the grace window the whole family is revoked |
| Revocation | `revoke()` kills one family, `revokeAllForUser()` kills every family of a user |
| Verification | `authenticate()` returns the user or `null`, so middleware never branches on exceptions |
| Exceptions | `TokenAuthException` extends `SecurityException`, so existing catch blocks keep working |

## Using your own storage

Implement `TokenStoreInterface` (database, Redis, …). The backing table needs an index on
`family_id` and `user_id`, because revocation works by family and by user.

```php
use MiGears\TokenAuth\TokenRecord;
use MiGears\TokenAuth\TokenStoreInterface;

final class PdoTokenStore implements TokenStoreInterface
{
    public function save(string $hash, TokenRecord $record): void        { /* upsert */ }
    public function find(string $hash): ?TokenRecord                     { /* select + fromArray */ }
    public function delete(string $hash): void                           { /* delete one */ }
    public function deleteByFamily(string $familyId): void               { /* delete where family_id */ }
    public function deleteByUser(string $userId): void                   { /* delete where user_id */ }
    public function pruneExpired(int $now): int                          { /* delete expired rows */ }
}
```

`ArrayTokenStore` is an in-memory reference implementation for tests and single-process workers, not
a production store. `pruneExpired()` is never called by the module itself — run it from a scheduled
job, because used refresh records are deliberately kept until they expire so that a replay stays
distinguishable from a random guess.

## Design decisions

- **Opaque tokens, not JWT.** A JWT removes the per-request store lookup but cannot be revoked before
  it expires. Revocation wins here; `TokenPair::toArray()` still speaks the OAuth 2.0 token response,
  so a JWT layer can be swapped in behind your middleware.
- **A grace window on replay.** Mobile clients legitimately retry a refresh when a response is lost.
  Inside `reuseGracePeriod` seconds a replayed token answers "already used" and keeps the family;
  outside it, the family is revoked. Set `reuseGracePeriod: 0` for strict behaviour.
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

# migears-token-auth（中文）

面向原生 App 及其他非浏览器客户端的 Bearer 令牌认证：短期不透明 access token、一次性轮换的
refresh token、重放检测，以及只存哈希的服务端存储。

它是 `migears-security` 浏览器会话实现（`MiAuth`）之外的第二条认证通道。两者除“你自己的用户查询”
外没有任何共享。

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

## 安装

```bash
composer require migears/token-auth
```

本地对着同级目录开发时，`composer.json` 已声明指向 `../migears-security` 的 `path` 仓库。

## 快速开始

```php
use MiGears\TokenAuth\ArrayTokenStore;
use MiGears\TokenAuth\TokenAuth;

$auth = new TokenAuth(
    store: new ArrayTokenStore(),          // 生产环境换成 DB / Redis 实现
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
| 存储 | 只存 `sha256(token)`，从不存令牌本身 |
| 轮换 | 每次刷新消费被出示的 refresh token，并签发新一对 |
| 重放 | 已消费令牌再次出现即拒绝；超出宽限期则撤销整个族 |
| 撤销 | `revoke()` 撤销一个族，`revokeAllForUser()` 撤销该用户全部族 |
| 校验 | `authenticate()` 返回用户或 `null`，中间件无需处理异常分支 |
| 异常 | `TokenAuthException` 继承 `SecurityException`，既有 catch 块无需改动 |

## 使用自己的存储

实现 `TokenStoreInterface`（数据库、Redis 等）。底层表需要对 `family_id` 与 `user_id` 建索引，
因为撤销按族、按用户进行。

```php
use MiGears\TokenAuth\TokenRecord;
use MiGears\TokenAuth\TokenStoreInterface;

final class PdoTokenStore implements TokenStoreInterface
{
    public function save(string $hash, TokenRecord $record): void        { /* upsert */ }
    public function find(string $hash): ?TokenRecord                     { /* select + fromArray */ }
    public function delete(string $hash): void                           { /* 删除单条 */ }
    public function deleteByFamily(string $familyId): void               { /* delete where family_id */ }
    public function deleteByUser(string $userId): void                   { /* delete where user_id */ }
    public function pruneExpired(int $now): int                          { /* 删除过期记录 */ }
}
```

`ArrayTokenStore` 是内存版参考实现，适用于测试与单进程场景，不是生产存储。`pruneExpired()` 从不被
模块自身调用——请用定时任务执行；已使用的 refresh 记录会被刻意保留至过期，以便让重放与随机猜测保持
可区分。

## 设计取舍

- **不透明令牌，而非 JWT。** JWT 能省掉每请求一次存储读取，但无法在过期前撤销。这里选择可撤销；
  `TokenPair::toArray()` 仍遵循 OAuth 2.0 令牌响应，因此可在中间件后面换成 JWT 实现。
- **重放宽限期。** 移动端在响应丢失时确实会重试刷新。在 `reuseGracePeriod` 秒内，重放回答“已使用”
  并保留令牌族；超出则撤销令牌族。设 `reuseGracePeriod: 0` 即严格模式。
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
