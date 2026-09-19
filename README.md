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
- `Measurement(round_index, nonce, response, elapsed_seconds, distance_meters)`
- `ChallengeStateError(ValueError)` — 挑战状态不合法（未登记、他实例签发、已消费或已撤销）；继承 `ValueError`
- `Prover(shared_key)` — `respond(challenge) -> bytes`，HMAC-SHA256 应答
- `Verifier(shared_key, *, speed_mps=SPEED_OF_LIGHT_MPS, clock=time.perf_counter, replay_protection=False)`
  - `new_challenge()` — 生成 16 字节随机 nonce
  - `verify(challenge, response, started_at)` — 校验应答并把往返时间折半换算为距离
  - `measure(prover)` — 一次完整往返
  - `revoke(challenge)` — 撤销本实例仍待验证的挑战（仅保护模式下可用）
  - `clock` — 只读属性，暴露计时函数
  - `replay_protection` — 只读属性，指示是否开启重放防护
- `SPEED_OF_LIGHT_MPS` — 默认传播速度常量

### 重放防护（可选，默认关闭）

`Verifier(..., replay_protection=True)` 后，每个 `new_challenge()` 都登记为本实例的待验证挑战，挑战状态同时绑定**签发实例与挑战完整内容**（`round_index` + `nonce`），而非仅靠可碰撞的轮次号：

- `verify` 只接受同一实例签发且仍待验证的挑战；外部构造、其他实例签发、已成功验证、已撤销的挑战都抛出 `ChallengeStateError`。
- 响应不匹配、负耗时、参数类型错误等失败**不会消费**挑战，修正后可重试；仅当成功返回 `Measurement` 时才原子标记为已消费，并发调用同一挑战至多一次成功。
- `revoke(challenge)` 只能撤销本实例仍待验证的挑战；撤销后不可再验证；撤销未知、已消费或重复撤销均抛出 `ChallengeStateError`。
- `measure` 在保护模式下遵循同一套规则。

默认 `replay_protection=False` 时，`verify`、`measure` 及数据结构行为与之前完全一致：外部构造的挑战仍可验证、成功挑战可重放。

## 限制

当前是单验证者的朴素往返测距：挑战先发出、应答后到达，两者之间没有任何延迟承诺，应答正确性也不绑定到挑战发出时刻。距离直接由一次往返时间换算，未做噪声估计、未做统计判定，也未在多轮之间做一致性检查。默认模式下 nonce 只保证随机，不记录已用集合；需要单挑战单次消费语义时请显式开启 `replay_protection`（状态仅保存在 `Verifier` 实例内存中，不跨进程持久化）。

## 测试

```bash
python3 -m unittest discover -s tests
```
