# nearproof

可验证的距离测量与位置证明协议库。验证者发出挑战，证明者返回带密钥的应答，验证者用往返时间估出距离上界。

## 环境

Python 3.10+，只依赖标准库（`hashlib`、`hmac`、`secrets`、`time`）。

## 使用

```python
from nearproof import Prover, Verifier

key = b"\x01" * 32
prover, verifier = Prover(key), Verifier(key)

challenge = verifier.new_challenge()
started = verifier.clock()
response = prover.respond(challenge)
measurement = verifier.verify(challenge, response, started)
print(measurement.distance_meters)
```

## 命令行演示

```bash
python3 -m nearproof
```

## 公开接口

- `Challenge(round_index, nonce)` — 验证者发出的挑战
- `ChallengeStateError(ValueError)` — 挑战未由本验证者签发、已成功验证、已撤销或已过期
- `Evidence(version, round_index, nonce, response, start, end, speed, elapsed, distance, result, mac)` — 一轮已接受往返的防篡改证据记录（冻结数据类）
- `Measurement(round_index, nonce, response, elapsed_seconds, distance_meters)`
- `Prover(shared_key)` — `respond(challenge) -> bytes`，HMAC-SHA256 应答
- `Verifier(shared_key, *, speed_mps=SPEED_OF_LIGHT_MPS, clock=time.perf_counter, replay_protection=False, challenge_ttl_seconds=None)`
  - `new_challenge()` — 生成 16 字节随机 nonce；配置有效期时按 `clock()` 记录签发时刻
  - `verify(challenge, response, started_at)` — 校验应答并把往返时间折半换算为距离
  - `verify_evidence(challenge, response, started_at)` — 同 `verify`，但返回带密钥 MAC 的 `Evidence`
  - `measure(prover)` — 一次完整往返
  - `revoke(challenge)` — 显式撤销一个仍待验证的挑战（仅在 `replay_protection=True` 时可用）
  - `clock` — 只读属性，暴露计时函数
- `audit(evidence, key)` — 复核 `Evidence`（或其字节编码）并返回对应的 `Measurement`
- `SPEED_OF_LIGHT_MPS` — 默认传播速度常量

### 重放防护

`replay_protection` 默认为 `False`，此时保持单轮测距的原有行为：外部构造的挑战、重复验证均不报错。

开启后，`new_challenge()` 登记的挑战进入待验证状态，`verify` 只接受**同一实例签发、内容完全一致且仍待验证**的那个挑战对象：外部构造、同内容副本、其他实例签发、`round_index` 碰撞、已成功验证或已 `revoke` 的挑战都会抛出 `ChallengeStateError`。应答不匹配、负耗时、参数类型错误等失败不消费挑战，修正后可重试；只有成功返回 `Measurement` 才原子地转为已消费，并发调用中同一挑战至多成功一次。

```python
verifier = Verifier(key, replay_protection=True)
challenge = verifier.new_challenge()
verifier.verify(challenge, prover.respond(challenge), verifier.clock())
verifier.verify(challenge, prover.respond(challenge), verifier.clock())  # ChallengeStateError
```

### 挑战有效期

`challenge_ttl_seconds` 仅限关键字传入，默认 `None` 表示永不过期、行为与旧版完全一致。传入非 `None` 值时：

- 必须是非布尔的有限正数（`int`/`float`，排除 `bool`、零、负数、`inf`、`nan` 及非数值类型），否则抛出 `ValueError`；
- 必须同时设置 `replay_protection=True`，否则抛出 `ValueError`。

配置后，`new_challenge()` 在登记时读取一次 `clock()` 作为签发时刻，截止时刻 = 签发时刻 + 有效期。`verify` 与 `revoke` 每次调用只读一次时钟：**当前值严格小于截止时刻才有效，等于或大于即过期**。过期是终态——过期挑战会被钉为 `expired`，之后对其调用 `verify` 或 `revoke` 一律抛出 `ChallengeStateError`，时钟回拨也不能复活；未知、已消费、已撤销的挑战仍按原有状态规则处理，且状态与到期判定先于应答、耗时和参数类型校验。

错误应答、负耗时或参数类型错误不会刷新签发时刻、不会延长截止时刻；修正后只能在原截止时刻之前重试。`measure(prover)` 遵循相同规则：若应答期间时钟到达或跨过截止时刻，该轮直接失败。状态、到期与消费判定在同一把锁内完成，因此截止时刻之前并发验证至多一次成功，截止时刻及以后全部失败。

```python
verifier = Verifier(key, replay_protection=True, challenge_ttl_seconds=0.05)
challenge = verifier.new_challenge()          # 签发时刻 t，截止时刻 t + 0.05
verifier.verify(challenge, prover.respond(challenge), verifier.clock())  # 截止前成功
# 另一个挑战在 t + 0.05 或之后验证 -> ChallengeStateError("challenge has expired")
```

### 证据记录与审计

`verify_evidence(challenge, response, started_at)` 的参数、状态规则、有效期判定、校验顺序和原子消费与 `verify` 完全一致，区别只在返回值和新的一类校验：

- 成功时返回 `Evidence`：`version` 恒为 1，`result` 恒为 `"accepted"`，`start=float(started_at)`，`end` 为本次调用唯一的时钟读数，`speed`/`elapsed`/`distance` 与 `verify` 的同轮结果一致；`mac` 是用共享密钥对除 `mac` 外全部字段的规范编码计算的 HMAC-SHA256，密钥本身不进入记录。
- 遇到非有限数（`nan`/`inf` 的 `started_at`、时钟读数、耗时或距离）时抛出 `ValueError` 且**不消费**挑战；`verify` 的行为不变，不做这一检查。

`Evidence.to_bytes()` 给出规范编码：无空白 UTF-8 JSON，键按字段顺序，字节字段用小写十六进制（`json.dumps(obj, separators=(",", ":"), allow_nan=False).encode()`）。`Evidence.from_bytes(data)` 是严格逆运算：非 `bytes`、非法 JSON、缺键/多键/键序不符、`version` 非 1、`result` 非 `"accepted"`、布尔或非有限数值、非小写十六进制、`mac` 非 32 字节等一律抛出 `ValueError`。

`audit(evidence, key)` 接受 `Evidence` 或其字节编码，拒绝空密钥；用 `key` 以恒时比较复核 MAC 和应答 HMAC，并按 `start`/`end`/`speed` 复算耗时与折半距离，任何不符都抛出 `ValueError`，全部通过则返回对应的 `Measurement`。审计只是对记录的纯复核：不触碰任何验证者状态，也不替代签发时的重放与有效期检查。

```python
evidence = verifier.verify_evidence(challenge, prover.respond(challenge), verifier.clock())
blob = evidence.to_bytes()                     # 可持久化或传输
measurement = audit(Evidence.from_bytes(blob), key)  # 复核通过 -> Measurement
```

## 限制

当前是单验证者的朴素往返测距：挑战先发出、应答后到达，两者之间没有任何延迟承诺，应答正确性也不绑定到挑战发出时刻（配置 `challenge_ttl_seconds` 后仅按验证者时钟限制挑战本身的有效期，并不约束证明者的应答时刻）。距离直接由一次往返时间换算，未做噪声估计、未做统计判定，也未在多轮之间做一致性检查。默认模式下 nonce 只保证随机，不记录已用集合；开启 `replay_protection` 后则按签发实例登记并追踪每个挑战的待验证 / 已消费 / 已撤销 / 已过期状态，但注册表（含截止时刻）仅保存在内存中、随实例生命周期结束，过期判定也完全信任注入的 `clock`。

## 测试

```bash
python3 -m unittest discover -s tests
```
