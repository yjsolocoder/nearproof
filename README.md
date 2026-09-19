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
- `Consensus(total, support, rejected, accepted)` — `locate` 的冻结共识结果：`rejected` 为不支持的验证者 id 按字典序排列的字符串元组
- `Evidence(version, round_index, nonce, response, start, end, speed, elapsed, distance, result, mac)` — 一轮已接受验证的防篡改记录（`version=1`、`result="accepted"`，不含密钥）
  - `to_bytes()` — 无空白 UTF-8 JSON 编码：键依字段顺序，bytes 字段为小写十六进制
  - `from_bytes(data)` — 按字段契约解码，非 bytes 或不合契约一律抛 `ValueError`（不校验 MAC）：JSON 对象的键必须恰好是十一个字段且各出现一次、顺序与字段顺序一致（重复或乱序即拒绝），`mac` 必须解码为恰好 32 字节
- `Measurement(round_index, nonce, response, elapsed_seconds, distance_meters)`
- `Observation(id, x, y, decision)` — 二维共识中一个验证者的冻结观察：`id` 为非空字符串，`(x, y)` 为非布尔有限数坐标，`decision` 为 `RangeDecision`（仅其有限非负的 `upper_bound` 参与共识，`accepted` 不参与）
- `Prover(shared_key)` — `respond(challenge) -> bytes`，HMAC-SHA256 应答
- `RangeDecision(sample_count, upper_bound, accepted)` — `assess` 的冻结结果：`sample_count` 统计全部输入样本（含离群点），`upper_bound` 为内点最大距离，`accepted` 表示其不超过 limit
- `Verifier(shared_key, *, speed_mps=SPEED_OF_LIGHT_MPS, clock=time.perf_counter, replay_protection=False, challenge_ttl_seconds=None)`
  - `new_challenge()` — 生成 16 字节随机 nonce；配置有效期时按 `clock()` 记录签发时刻
  - `verify(challenge, response, started_at)` — 校验应答并把往返时间折半换算为距离
  - `verify_evidence(challenge, response, started_at)` — 同 `verify` 的参数与语义，成功时返回 `Evidence`
  - `measure(prover)` — 一次完整往返
  - `revoke(challenge)` — 显式撤销一个仍待验证的挑战（仅在 `replay_protection=True` 时可用）
  - `clock` — 只读属性，暴露计时函数
- `assess(samples, limit, *, key=None, min_samples=5) -> RangeDecision` — 基于一批轮次的稳健距离判定（见下）
- `audit(evidence, key)` — 用共享密钥复核 `Evidence`（或其字节编码），返回对应的 `Measurement`
- `locate(observations, point, *, quorum=3, tolerance=0.0) -> Consensus` — 二维多验证者位置共识（见下）
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

`Evidence.to_bytes()` 按无空白 UTF-8 JSON 编码：键依字段顺序，bytes 字段为小写十六进制，即 `json.dumps(obj, separators=(",", ":"), allow_nan=False).encode()`；`mac` 是共享密钥对“同法编码的无 mac 键对象”的 HMAC-SHA256。`Evidence.from_bytes(data)` 执行字段契约校验——JSON 对象的键必须恰好是十一个字段、**各出现一次且顺序与字段顺序完全一致**（重复键或乱序即拒绝）、`version==1`、`result=="accepted"`、非布尔整数、有限数值（bool 不算数值）、小写十六进制、`mac` **必须解码为恰好 32 字节**——非 bytes 或不合契约一律抛 `ValueError`；它不校验 MAC。

`audit(evidence, key)` 接受 `Evidence` 或其字节编码，拒绝空 key：用 key 恒时复核 MAC 与应答 HMAC，并按 `start`/`end`/`speed` 复算耗时与折半距离，任何不符抛 `ValueError`，全部通过则返回对应的 `Measurement`。审计是纯函数，不触碰任何验证者状态，也不能替代验证时的重放防护与挑战有效期。

```python
evidence = verifier.verify_evidence(challenge, prover.respond(challenge), verifier.clock())
blob = evidence.to_bytes()                    # 可持久化或传输
measurement = audit(Evidence.from_bytes(blob), key)  # 复核通过则返回测量值
```

### 批量判定 `assess`

`assess(samples, limit, *, key=None, min_samples=5)` 对一批轮次做稳健的距离上界判定，返回冻结的 `RangeDecision(sample_count, upper_bound, accepted)`：

- `samples` 必须**全为 `Measurement`**，或**全为 `Evidence` / 其 `to_bytes()` 字节编码**（可混用 `Evidence` 对象与字节）；两类混用、包含任何其他类型、或不是可迭代对象，一律抛 `ValueError`。
- 证据样本必须提供非空 `key`：每项先按与 `audit` 完全相同的语义复核（MAC、应答 HMAC、耗时与距离复算），任一不符即抛 `ValueError`。
- 出现重复的 `(round_index, nonce)` 对、耗时或距离为负 / 非有限 / 非数值（`bool` 不算数值）均抛 `ValueError`。
- 样本总数少于 `min_samples` 抛 `ValueError`；`min_samples` 必须是非布尔正整数，`limit` 必须是非布尔、有限、非负数（`int`/`float`，排除 `bool`、负数、`inf`、`nan`、非数值类型）。

判定规则（只看距离）：取距离中位数 `m`（偶数个时取中间两值的均值）与绝对偏差中位数 `MAD`。`MAD > 0` 时，距离落在闭区间 `[m - 3*MAD, m + 3*MAD]` 内的样本为内点；`MAD == 0` 时仅距离恰等于 `m` 的样本为内点。内点少于 `min_samples` 抛 `ValueError`；否则 `upper_bound` 为内点最大距离，`accepted` 当且仅当 `upper_bound <= limit`。`sample_count` 记录**全部**输入样本数（含被判为离群点的样本）。

结果与输入顺序无关；`assess` 是纯计算：证据样本只经 `audit` 复核，不读取也不修改任何验证者状态。

```python
measurements = [verifier.measure(prover) for _ in range(10)]
decision = assess(measurements, limit=300.0)
if decision.accepted:
    print(decision.sample_count, decision.upper_bound)
```

### 二维多验证者共识 `locate`

`locate(observations, point, *, quorum=3, tolerance=0.0)` 在多个验证者对同一证明者给出的距离上界之间，对一个二维候选点做位置共识，返回冻结的 `Consensus(total, support, rejected, accepted)`。

每个输入是冻结的 `Observation(id, x, y, decision)`：`id` 必须是非空字符串且在全部观察中唯一，`x`/`y` 必须是非布尔有限数，`decision` 必须是 `RangeDecision`，其 `upper_bound` 必须有限非负——**共识只使用 `upper_bound`，`decision.accepted` 一律不参与**。

- `observations` 必须可迭代、至少含三个观察；非可迭代、元素不是 `Observation`、id 重复或为空、坐标或上界非法（`bool`、`inf`、`nan`、负数、非数值）均抛 `ValueError`。
- `point` 必须是**恰含两个非布尔有限数的 tuple**；长度不对、list、布尔或非有限数均抛 `ValueError`。
- `quorum` 必须是非布尔正整数且不大于观察数，`tolerance` 必须是非布尔有限非负数；二者仅限关键字传入，违约均抛 `ValueError`。

判定规则：对每个观察用 `math.hypot(point[0] - x, point[1] - y)` 求距离，当且仅当距离 `<= upper_bound + tolerance` 时该验证者支持该点——**边界等于时计入支持**，tolerance 的边界同样为闭区间。`total` 为观察总数，`support` 为支持者数，`rejected` 是不支持者 id 按字典序排列的 tuple，`accepted` 当且仅当 `support >= quorum`。

各验证者的圆盘互相矛盾（部分覆盖、部分不覆盖候选点）时不抛异常，而是如实体现在 `support` 与 `rejected` 中；是否接受只由法定人数决定。`rejected` 经过排序，结果与输入顺序无关，`locate` 是纯计算，不读取也不修改任何验证者状态。

```python
from nearproof import Observation, RangeDecision, locate

observations = [
    Observation("alpha", 0.0, 0.0, RangeDecision(5, 5.0, True)),
    Observation("bravo", 3.0, 0.0, RangeDecision(5, 5.0, False)),  # accepted 被忽略
    Observation("charlie", 0.0, 4.0, RangeDecision(5, 5.0, True)),
]
consensus = locate(observations, (0.0, 0.0))
consensus.total, consensus.support     # (3, 3)
consensus.rejected                     # ()
consensus.accepted                     # True
```

## 限制

当前是单验证者的朴素往返测距：挑战先发出、应答后到达，两者之间没有任何延迟承诺，应答正确性也不绑定到挑战发出时刻（配置 `challenge_ttl_seconds` 后仅按验证者时钟限制挑战本身的有效期，并不约束证明者的应答时刻）。单轮距离直接由一次往返时间换算；跨轮的稳健判定由 `assess` 在事后基于中位数 / MAD 离群点剔除完成，它不改变单轮验证语义，也不提供多轮间的密码学一致性。默认模式下 nonce 只保证随机，不记录已用集合；开启 `replay_protection` 后则按签发实例登记并追踪每个挑战的待验证 / 已消费 / 已撤销 / 已过期状态，但注册表（含截止时刻）仅保存在内存中、随实例生命周期结束，过期判定也完全信任注入的 `clock`。二维共识 `locate` 只把各验证者 `assess` 出的距离上界按圆盘覆盖做纯几何聚合：它不交叉验证观察来源、不绑定验证者身份与坐标的真实性，圆盘矛盾只表现为拒绝计数而非异常。

## 测试

```bash
python3 -m unittest discover -s tests
```
