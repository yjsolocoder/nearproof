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
- `Prover(shared_key)` — `respond(challenge) -> bytes`，HMAC-SHA256 应答
- `Verifier(shared_key, *, speed_mps=SPEED_OF_LIGHT_MPS, clock=time.perf_counter)`
  - `new_challenge()` — 生成 16 字节随机 nonce
  - `verify(challenge, response, started_at)` — 校验应答并把往返时间折半换算为距离
  - `measure(prover)` — 一次完整往返
  - `clock` — 只读属性，暴露计时函数
- `SPEED_OF_LIGHT_MPS` — 默认传播速度常量

## 限制

当前是单验证者的朴素往返测距：挑战先发出、应答后到达，两者之间没有任何延迟承诺，应答正确性也不绑定到挑战发出时刻。距离直接由一次往返时间换算，未做噪声估计、未做统计判定，也未在多轮之间做一致性检查。nonce 只保证随机，不记录已用集合。

## 测试

```bash
python3 -m unittest discover -s tests
```
