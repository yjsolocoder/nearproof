# nearproof

可验证的距离测量与位置证明协议库。验证者发出挑战，证明者返回带密钥的应答，验证者用往返时间估出距离上界。

## 环境

Python 3.10+，只依赖标准库（`hashlib`、`hmac`、`json`、`math`、`os`、`statistics`、`threading`、`time`）。

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
- `Evidence(version, round_index, nonce, response, start, end, speed, elapsed, distance, result, mac)` — 一轮已接受验证的防篡改记录（`version=1`、`result="accepted"`，不含密钥）
  - `to_bytes()` — 无空白 UTF-8 JSON 编码：键依字段顺序，bytes 字段为小写十六进制
  - `from_bytes(data)` — 按字段契约解码：键必须依字段顺序出现，`mac` 解码后须为 32 字节；非 bytes 或不合契约一律抛 `ValueError`（不校验 MAC）
- `Measurement(round_index, nonce, response, elapsed_seconds, distance_meters)`
- `Prover(shared_key)` — `respond(challenge) -> bytes`，HMAC-SHA256 应答
- `Verifier(shared_key, *, speed_mps=SPEED_OF_LIGHT_MPS, clock=time.perf_counter, replay_protection=False, challenge_ttl_seconds=None)`
  - `new_challenge()` — 生成 16 字节随机 nonce；配置有效期时按 `clock()` 记录签发时刻
  - `verify(challenge, response, started_at)` — 校验应答并把往返时间折半换算为距离
  - `verify_evidence(challenge, response, started_at)` — 同 `verify` 的参数与语义，成功时返回 `Evidence`
  - `measure(prover)` — 一次完整往返
  - `revoke(challenge)` — 显式撤销一个仍待验证的挑战（仅在 `replay_protection=True` 时可用）
  - `clock` — 只读属性，暴露计时函数
- `audit(evidence, key)` — 用共享密钥复核 `Evidence`（或其字节编码），返回对应的 `Measurement`
- `assess(samples, limit, *, key=None, min_samples=5)` — 对一批样本做统计判定，返回 `RangeDecision`
- `RangeDecision(sample_count, upper_bound, accepted)` — 冻结的判定结果
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

`verify_evidence(challenge, response, started_at)` 与 `verify` 参数相同，沿用其状态、有效期、校验顺序与原子消费语义，区别在于：

- 成功时返回冻结的 `Evidence` 记录（`version=1`、`result="accepted"`，不含密钥），其中 `start=float(started_at)`，`end` 为本次调用唯一的时钟读数；
- 任何将被记录的非有限数值（`started_at`、时钟读数及派生的耗时、速度、距离）都抛出 `ValueError`，且挑战保持待验证、不被消费；旧接口 `verify` 的行为不变。

`Evidence.to_bytes()` 按无空白 UTF-8 JSON 编码：键依字段顺序，bytes 字段为小写十六进制，即 `json.dumps(obj, separators=(",", ":"), allow_nan=False).encode()`；`mac` 是共享密钥对“同法编码的无 mac 键对象”的 HMAC-SHA256。`Evidence.from_bytes(data)` 执行字段契约校验——恰好十一个字段且键序与字段顺序一致、`version==1`、`result=="accepted"`、非布尔整数、有限数值（bool 不算数值）、小写十六进制、`mac` 解码后恰为 32 字节——非 bytes 或不合契约一律抛 `ValueError`；它不校验 MAC。

`audit(evidence, key)` 接受 `Evidence` 或其字节编码，拒绝空 key：用 key 恒时复核 MAC 与应答 HMAC，并按 `start`/`end`/`speed` 复算耗时与折半距离，任何不符抛 `ValueError`，全部通过则返回对应的 `Measurement`。审计是纯函数，不触碰任何验证者状态，也不能替代验证时的重放防护与挑战有效期。

```python
evidence = verifier.verify_evidence(challenge, prover.respond(challenge), verifier.clock())
blob = evidence.to_bytes()                    # 可持久化或传输
measurement = audit(Evidence.from_bytes(blob), key)  # 复核通过则返回测量值
```

### 批量统计判定

`assess(samples, limit, *, key=None, min_samples=5)` 把多轮样本汇总为一个距离上界判定，返回冻结的 `RangeDecision(sample_count, upper_bound, accepted)`：

- `samples` 必须全为 `Measurement`，或全为 `Evidence` / 其 `to_bytes()` 编码（这两类可互相混用）；后者逐项按 `audit` 语义用非空 `key` 核验，核验失败即抛 `ValueError`。
- 类型混用、重复 `(round_index, nonce)`、耗时或距离为负或非有限、样本总数少于 `min_samples`，均抛 `ValueError`；`limit` 须为非布尔的有限非负数，`min_samples` 须为非布尔正整数。
- 取距离中位数 `m`（偶数个取中间两值均值）与绝对偏差中位数 MAD：`MAD > 0` 时闭区间 `[m - 3*MAD, m + 3*MAD]` 内为内点，`MAD == 0` 时仅等于 `m` 的样本为内点；内点少于 `min_samples` 抛 `ValueError`。
- `upper_bound` 为内点中的最大距离，`accepted` 当且仅当 `upper_bound <= limit`；`sample_count` 记录全部输入样本数（含离群点）。

判定结果与输入顺序无关，`assess` 是纯函数，不触碰任何验证者状态。

```python
samples = [verifier.measure(prover) for _ in range(5)]
decision = assess(samples, limit=150.0)
if decision.accepted:
    print("距离上界", decision.upper_bound)
```

## 限制

当前是单验证者的朴素往返测距：挑战先发出、应答后到达，两者之间没有任何延迟承诺，应答正确性也不绑定到挑战发出时刻（配置 `challenge_ttl_seconds` 后仅按验证者时钟限制挑战本身的有效期，并不约束证明者的应答时刻）。距离直接由一次往返时间换算，未做噪声建模；多轮之间的一致性检查由 `assess` 以中位数 / MAD 做稳健判定，但不替代验证时的重放防护与挑战有效期。默认模式下 nonce 只保证随机，不记录已用集合；开启 `replay_protection` 后则按签发实例登记并追踪每个挑战的待验证 / 已消费 / 已撤销 / 已过期状态，但注册表（含截止时刻）仅保存在内存中、随实例生命周期结束，过期判定也完全信任注入的 `clock`。

## 测试

```bash
python3 -m unittest discover -s tests
```
