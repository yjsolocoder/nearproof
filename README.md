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
- `Measurement(round_index, nonce, response, elapsed_seconds, distance_meters)`
- `Prover(shared_key)` — `respond(challenge) -> bytes`，HMAC-SHA256 应答
- `Verifier(shared_key, *, speed_mps=SPEED_OF_LIGHT_MPS, clock=time.perf_counter, replay_protection=False, challenge_ttl_seconds=None)`
  - `new_challenge()` — 生成 16 字节随机 nonce；配置有效期时同时记录签发时刻
  - `verify(challenge, response, started_at)` — 校验应答并把往返时间折半换算为距离
  - `measure(prover)` — 一次完整往返
  - `revoke(challenge)` — 显式撤销一个仍待验证的挑战（仅在 `replay_protection=True` 时可用）
  - `clock` — 只读属性，暴露计时函数
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

`challenge_ttl_seconds`（仅限关键字，默认 `None`）为重放防护模式增加基于验证者 `clock` 的有效期。`None` 表示永不过期，行为与之前完全一致；非 `None` 值必须是非布尔的有限正数，且必须同时设置 `replay_protection=True`，否则构造时抛出 `ValueError`。

配置后，`new_challenge()` 记录签发时的 `clock()` 值，截止时刻为签发时刻加有效期。每次 `verify` / `revoke` 只读取一次时钟：当前值**严格小于**截止时刻才有效，等于或大于即过期。过期是终态——此后对该挑战调用 `verify` 或 `revoke` 都抛出 `ChallengeStateError`，即使时钟回拨也不恢复。错误应答、负耗时或参数类型错误不会刷新签发时刻或延长有效期，修正后只能在原截止时刻前重试。状态判定（未知 / 已消费 / 已撤销 / 已过期）先于应答校验，且与消费判定在同一把锁内完成：截止前并发调用至多一次成功，截止时刻及以后全部失败。`measure(prover)` 遵循同一规则，应答期间跨过截止时刻即失败。

```python
verifier = Verifier(key, replay_protection=True, challenge_ttl_seconds=0.5)
challenge = verifier.new_challenge()
# 0.5 秒内 verify 有效；到达或超过截止时刻后:
verifier.verify(challenge, prover.respond(challenge), verifier.clock())  # ChallengeStateError
```

## 限制

当前是单验证者的朴素往返测距：挑战先发出、应答后到达，两者之间没有任何延迟承诺，应答正确性也不绑定到挑战发出时刻。距离直接由一次往返时间换算，未做噪声估计、未做统计判定，也未在多轮之间做一致性检查。默认模式下 nonce 只保证随机，不记录已用集合；开启 `replay_protection` 后则按签发实例登记并追踪每个挑战的待验证 / 已消费 / 已撤销状态，配置 `challenge_ttl_seconds` 时另有已过期终态，但注册表仅保存在内存中、随实例生命周期结束。有效期完全以验证者本地 `clock` 为准，不防御时钟本身被操纵。

## 测试

```bash
python3 -m unittest discover -s tests
```
