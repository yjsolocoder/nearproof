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
- `Prover(shared_key)` — `respond(challenge) -> bytes`（HMAC-SHA256 应答）；`reveal(challenge, context, opening) -> bytes` 用于上下文绑定轮次（见下）
- `RangeDecision(sample_count, upper_bound, accepted)` — `assess` 的冻结结果：`sample_count` 统计全部输入样本（含离群点），`upper_bound` 为内点最大距离，`accepted` 表示其不超过 limit
- `Verifier(shared_key, *, speed_mps=SPEED_OF_LIGHT_MPS, clock=time.perf_counter, replay_protection=False, challenge_ttl_seconds=None)`
  - `new_challenge(*, context=None, digest=None)` — 默认（均为 `None`）生成 16 字节随机 nonce，行为与旧版一致；成对传入 32 字节 `context`/`digest` 则签发上下文绑定挑战（要求 `replay_protection=True`，只传一个抛 `ValueError`）；配置有效期时按 `clock()` 记录签发时刻
  - `verify(challenge, response, started_at, *, opening=None) -> Measurement` — 校验应答并把往返时间折半换算为距离；`opening=None` 为旧行为，传入 32 字节 `opening` 则走上下文绑定协议（见下）
  - `verify_evidence(challenge, response, started_at)` — 同 `verify` 的参数与语义，成功时返回 `Evidence`
  - `verify_bound(challenge, response, started_at, *, opening) -> BoundEvidence` — 仅限上下文绑定挑战的 `verify_evidence`（见下）
  - `measure(prover)` — 一次完整往返
  - `revoke(challenge)` — 显式撤销一个仍待验证的挑战（仅在 `replay_protection=True` 时可用）
  - `clock` — 只读属性，暴露计时函数
- `assess(samples, limit, *, key=None, min_samples=5) -> RangeDecision` — 基于一批轮次的稳健距离判定（见下）
- `audit(evidence, key)` — 用共享密钥复核 `Evidence`（或其字节编码），返回对应的 `Measurement`
- `BoundEvidence(version, evidence, context, digest, opening, mac)` — 一轮已接受**上下文绑定**验证的防篡改记录（`version=1`，四个 bytes 字段均恰 32 字节，不含密钥；见下）
  - `to_bytes()` — 无空白 UTF-8 JSON 编码：键依字段顺序，`evidence` 为规范嵌套对象，bytes 字段为小写十六进制
  - `from_bytes(data)` — 按字段契约解码并重编码逐字节比对，非 bytes 或不合契约一律抛 `ValueError`（不校验 MAC）
- `audit_bound(bound, key)` — 用共享密钥复核 `BoundEvidence`（或其字节编码），返回对应的 `Measurement`
- `audit_bound_policy(bound, key, *, now=None, max_age=None) -> Measurement` — 先按 `audit_bound` 复核，再可选做时效复核（见下）
- `locate(observations, point, *, quorum=3, tolerance=0.0) -> Consensus` — 二维多验证者位置共识（见下）
- `AttestedObservation(version, id, x, y, decision, issued_at, mac)` — 带 HMAC 签名与时间戳的冻结观察（`version=1`，不含密钥；见下）
  - `to_bytes()` — 无空白 UTF-8 JSON 编码：键依字段顺序，`decision` 为嵌套对象且键同样依字段顺序，`mac` 为小写十六进制
  - `from_bytes(data)` — 按字段契约解码，非 bytes 或不合契约一律抛 `ValueError`（不校验 MAC）：外层与嵌套 `decision` 对象的键都必须恰好是各自字段、各出现一次且依字段顺序（缺、多、重复或乱序即拒绝），`mac` 必须解码为恰好 32 字节
- `attest_observation(id, x, y, decision, issued_at, key) -> AttestedObservation` — 用非空 key 对观察签名（见下）
- `locate_attested(observations, point, keys, *, quorum=3, tolerance=0.0, now=None, max_age=None, revocations=None) -> Consensus` — 先验签/验时效/验撤销再按 `locate` 规则聚合（见下）
- `BoundAttestedObservation(version, id, x, y, decision, point, context, issued_at, mac)` — 签名额外绑定候选点与用途的冻结观察（`version=1`，不含密钥；见下）
  - `to_bytes()` — 无空白 UTF-8 JSON 编码：键依字段顺序，`decision` 嵌套对象键依字段顺序，`point` 为裸二元 JSON 数组（无类型标签、无长度前缀），`mac` 为小写十六进制；整份即单个 JSON 文档，域标签为空、无任何长度前缀或额外定界
  - `from_bytes(data)` — 按字段契约解码并重编码逐字节比对，非 bytes 或不合契约一律抛 `ValueError`（不校验 MAC）
- `attest_observation_for_point(id, x, y, decision, point, context, issued_at, key) -> BoundAttestedObservation` — 用非空 key 签名一条绑定点与用途的观察（见下）
- `locate_bound_attested(observations, point, context, keys, *, quorum=3, tolerance=0.0, now=None, max_age=None, revocations=None) -> Consensus` — 恒时验签后还要求点逐项相等、用途精确相等，其余同 `locate_attested`（见下）
- `ObservationRevocation(version, id, revoked_at, mac)` — 带 HMAC 签名的冻结撤销记录（`version=1`，不含密钥；见下）
  - `to_bytes()` — 无空白 UTF-8 JSON 编码：键依字段顺序，`mac` 为小写十六进制
  - `from_bytes(data)` — 按字段契约解码并重编码逐字节比对，非 bytes 或不合契约一律抛 `ValueError`（不校验 MAC）
- `revoke_observation(id, revoked_at, key) -> ObservationRevocation` — 用非空 key 签发撤销记录（见下）
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

### 上下文绑定的挑战 / 应答（context commitment）

在普通往返之外，协议支持把一轮挑战绑定到一个 32 字节的用途上下文 `context` 与一个由证明者持有的 32 字节秘密 `opening` 上：

- 承诺 `digest = SHA256(b"NPC1" + context + opening)`，三者（`context`、`opening`、`digest`）均为 32 字节，拼接时**无任何分隔符或长度前缀**。
- 验证者调用 `new_challenge(context=context, digest=digest)` 签发绑定挑战：`context` 与 `digest` 必须**同时给出**（只给一个抛 `ValueError`），各自必须恰好 32 字节（长度不对抛 `ValueError`，非 bytes 抛 `TypeError`），并且必须开启 `replay_protection=True`（否则抛 `ValueError`），以便把该绑定连同挑战一起登记。返回的 `Challenge` 对象形状不变，仍是 `(round_index, nonce)`；`round_index` 为 u64 语义的非布尔整数，`nonce` 为 16 字节。
- 两参数均为 `None`（默认，且不允许按位置传入）时完全保持旧行为：普通 nonce 挑战，无需重放防护。
- 证明者用 `Prover.reveal(challenge, context, opening) -> bytes` 应答。它先校验 `context`/`opening` 均为恰好 32 字节的 bytes（形状错抛 `TypeError`，长度错抛 `ValueError`），再计算应答：
  `HMAC-SHA256(key, b"NPR1" + digest + u64be(round_index) + nonce)`，其中 `u64be` 为固定 **8 字节无符号大端**编码（`round_index` 必须是非布尔、取值在 `0..2^64-1` 的整数，`nonce` 恰好 16 字节，否则抛 `ValueError`/`TypeError`）。
- 验证者用 `verify(challenge, response, started_at, *, opening=opening)` 完成绑定轮次：`opening` 仅限关键字传入且必须恰好 32 字节；验证者用登记的 `context`/`digest` 检查 `SHA256(b"NPC1" + context + opening) == digest`（恒时比较），不匹配或长度不对抛 `ValueError`，`opening` 非 bytes 抛 `TypeError`，随后用同一 `NPR1` 公式恒时复核应答。状态、有效期、测距与原子消费语义与普通 `verify` 完全一致：状态/到期/负耗时等检查先于绑定与应答校验，绑定或应答失败不消费挑战、可在原截止时刻前重试。
- 协议模式不能混用：对**绑定**挑战用 `opening=None`（普通应答）、或对**普通**挑战传入 `opening`，一律抛 `ValueError`。`opening=None` 时普通挑战的旧行为不变；`verify_evidence`、`measure` 等其余接口不受影响。

```python
import hashlib
import os

from nearproof import Prover, Verifier

context = os.urandom(32)
opening = os.urandom(32)
digest = hashlib.sha256(b"NPC1" + context + opening).digest()

prover, verifier = Prover(key), Verifier(key, replay_protection=True)
challenge = verifier.new_challenge(context=context, digest=digest)
response = prover.reveal(challenge, context, opening)
measurement = verifier.verify(challenge, response, verifier.clock(), opening=opening)
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

### 绑定证据记录 `BoundEvidence` 与 `audit_bound`

`verify_bound(challenge, response, started_at, *, opening)` 是上下文绑定轮次的 `verify_evidence`：**仅限** `new_challenge(context=..., digest=...)` 签发的绑定挑战（未绑定挑战、或未开启重放防护的验证者一律抛 `ValueError`），`opening` 仅限关键字且必需——非 bytes（含 `None`）抛 `TypeError`，长度或承诺不匹配抛 `ValueError`。状态、有效期、校验顺序（状态/到期 → 测距 → 绑定与应答）与原子消费语义和 `verify_evidence` 完全一致：挑战状态与 TTL 检查先于一切 opening 类型、长度、承诺与应答检查（未知/已消费/已撤销/已过期的挑战即使 opening 畸形也抛 `ChallengeStateError`），任何失败都不消费挑战；任何将被记录的非有限数值抛 `ValueError` 且不消费挑战。

成功时返回冻结的 `BoundEvidence(version, evidence, context, digest, opening, mac)`：`version=1`；`evidence` 为本轮的 `Evidence`（与 `verify_evidence` 同样用共享密钥计算内层 MAC）；`context`/`digest`/`opening` 为登记的承诺三元组（均恰 32 字节）；`mac = HMAC-SHA256(key, b"NPBE1" + 去 mac 的规范编码)`。构造时即校验字段契约（`version==1`、四个 bytes 字段恰 32 字节、内层证据合法），违约抛 `ValueError`；记录不含密钥。

`to_bytes()` 按无空白 UTF-8 JSON 编码：键依字段顺序（`version, evidence, context, digest, opening, mac`），`evidence` 为键序同 `Evidence` 字段序的规范嵌套对象（含其自身 `mac`），bytes 字段为小写十六进制。`from_bytes(data)` 要求外层与嵌套对象的键都恰好是各自字段、各出现一次且依字段顺序，四个 bytes 字段均为解码后恰 32 字节的小写十六进制，并在解析与字段校验后重编码逐字节比对；非 bytes 或不合契约一律抛 `ValueError`，它不校验 MAC。

`audit_bound(bound, key)` 接受 `BoundEvidence` 或其字节编码，拒绝空 key，依次恒时复核四项——外层 `NPBE1` MAC、内层证据 MAC、承诺 `SHA256(b"NPC1" + context + opening) == digest`、绑定应答 `HMAC-SHA256(key, b"NPR1" + digest + u64be(round_index) + nonce)`——再按 `start`/`end`/`speed` 复算耗时与折半距离；任何不符抛 `ValueError`，全部通过则返回对应的 `Measurement`。审计是纯函数，不触碰任何验证者状态。

`audit_bound_policy(bound, key, *, now=None, max_age=None)` 在 `audit_bound` 的全部密码学、规范编码与测距复核（及其 `ValueError` 语义）完全不变的基础上，增加可选的时效复核：`max_age=None`（默认）时不做时效检查——`now` 被完全忽略且不读取任何时钟；否则 `max_age` 必须是非布尔、有限、非负的数，`now` 为必传的非布尔有限数（不提供或违约均抛 `ValueError`）。启用时以已审计的 `bound.evidence.end` 为签发完成时刻，必须满足闭区间 `0 <= now - end <= max_age`——未来或超龄证据抛 `ValueError`，两端边界相等均有效。与 `audit_bound` 一样，它是纯函数：不触碰任何验证者状态与挑战生命周期。

```python
challenge = verifier.new_challenge(context=context, digest=digest)
response = prover.reveal(challenge, context, opening)
bound = verifier.verify_bound(challenge, response, verifier.clock(), opening=opening)
blob = bound.to_bytes()                          # 可持久化或传输
measurement = audit_bound(BoundEvidence.from_bytes(blob), key)
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

### 带签名的观察 `AttestedObservation` 与 `locate_attested`

`AttestedObservation(version, id, x, y, decision, issued_at, mac)` 是冻结的带签名观察记录，构造时即校验全部字段契约，任何违约抛 `ValueError`：`version` 必须为 `1`；`id` 为非空字符串；`x`/`y`/`issued_at` 为非布尔、有限、非负的数；`decision` 为 `RangeDecision`，其 `sample_count` 为正整数（`bool` 不算）、`upper_bound` 有限非负、`accepted` 必须为 `bool`；`mac` 为恰好 32 字节的 `bytes`。`mac` 是共享密钥对“规范编码的无 mac 对象”的 HMAC-SHA256，记录本身不含密钥。

`to_bytes()` 按无空白 UTF-8 JSON 编码：外层键依字段顺序（`version, id, x, y, decision, issued_at, mac`），`decision` 编码为键依 `sample_count, upper_bound, accepted` 顺序的嵌套对象，`mac` 为小写十六进制。`from_bytes(data)` 执行字段契约校验——键必须恰好是各自字段、**各出现一次且顺序一致**（缺、多、重复或乱序即拒绝，嵌套 `decision` 同样）——并在解析与字段校验后按同一规范**重编码，与输入字节逐字节精确比较**：带缩进或字段间/首尾空白、非规范的数字或字符串写法（如 `3` 代替 `3.0`、多余的转义）均抛 `ValueError`；它不校验 MAC。

`attest_observation(id, x, y, decision, issued_at, key)` 用非空 `key` 签名一条观察（`version` 固定为 1），字段违约或空 key 均抛 `ValueError`；签名是纯计算，不触碰任何验证者状态。

`locate_attested(observations, point, keys, *, quorum=3, tolerance=0.0, now=None, max_age=None, revocations=None)` 在验签之后按 `locate` 的精确规则聚合：

- `observations` 可混用 `AttestedObservation` 对象与其 `to_bytes()` 字节编码；其他类型一律抛 `ValueError`。
- `keys` 必须是非空映射，把观察 id 映射到该验证者的非空共享密钥字节。每条记录用 `keys[id]` 恒时复核 MAC；**未知 id、重复 id、错误的 key 或任何篡改均抛 `ValueError`**。
- `max_age=None`（默认）不做时效检查；否则 `max_age` 必须是非布尔、有限、非负的数，且每条记录须满足 `0 <= now - issued_at <= max_age`（闭区间），`now` 缺省为 `time.time()`，显式传入时必须是非布尔有限数；过期或“来自未来”的记录抛 `ValueError`。
- `revocations=None`（默认）不做撤销检查，行为与之前完全一致。否则 `revocations` 必须是可迭代对象，可混用 `ObservationRevocation` 对象与其规范字节编码：每条撤销用 `keys[id]` 恒时复核 MAC，**未知或重复 id、错误 key、篡改、非法项一律抛 `ValueError`**；此时 `now` 同样必需（非布尔有限数，缺省时仅读一次 `time.time()`），`revoked_at > now` 的“未来撤销”抛 `ValueError`。若某观察的 `issued_at <=` 同 id 撤销的 `revoked_at`，抛 `ValueError`；**严格晚于撤销时刻**签发的观察不受影响，沿用原时效与几何规则。
- 验签通过的记录转为 `Observation` 后交给 `locate`（含 `quorum`/`tolerance` 校验与至少三条观察等全部规则），返回其 `Consensus`。`locate_attested` 是纯函数，除缺省读取一次 `time.time()` 外无副作用。

```python
import time

from nearproof import RangeDecision, attest_observation, locate_attested

keys = {"alpha": b"\x01" * 32, "bravo": b"\x02" * 32, "charlie": b"\x03" * 32}
now = time.time()
observations = [
    attest_observation("alpha", 0.0, 0.0, RangeDecision(5, 5.0, True), now, keys["alpha"]),
    attest_observation("bravo", 3.0, 0.0, RangeDecision(5, 5.0, False), now, keys["bravo"]),
    attest_observation("charlie", 0.0, 4.0, RangeDecision(5, 5.0, True), now, keys["charlie"]),
]
consensus = locate_attested(observations, (0.0, 0.0), keys, max_age=60.0)
consensus.accepted                     # True
```

### 绑定点与用途的观察 `BoundAttestedObservation` 与 `locate_bound_attested`

`BoundAttestedObservation(version, id, x, y, decision, point, context, issued_at, mac)` 在 `AttestedObservation` 的字段之外，让签名额外覆盖两个字段：`point` 为**恰含两个非布尔有限数的 tuple**（允许负数，与 `locate` 的查询点同契约，但不允许 list、布尔、`inf`/`nan` 或长度不为 2）；`context` 为**非空字符串**，标明该观察绑定的用途。其余字段契约与 `AttestedObservation` 完全一致：`version==1`、非空 `id`、非布尔有限非负的 `x`/`y`/`issued_at`、同一 `RangeDecision` 规则、`mac` 恰好 32 字节；构造时违约一律抛 `ValueError`。`mac` 仍是共享密钥对“规范编码的无 mac 对象”的 HMAC-SHA256。

`to_bytes()` 沿用无空白 UTF-8 JSON 与小写十六进制 `mac` 的规范编码：键依字段顺序（`version, id, x, y, decision, point, context, issued_at, mac`），`decision` 仍为键序固定的嵌套对象；区别是 `point` 编码为**裸的二元 JSON 数组**（如 `[0.0,1.5]`），既无类型标签也无长度前缀。整份输出就是单个 JSON 文档：域标签为空、没有长度前缀、没有额外定界。`from_bytes(data)` 的规则与 `AttestedObservation.from_bytes` 相同（键集合与顺序、嵌套 decision、十六进制 mac、解析后重编码逐字节比对），并额外要求 `point` 是恰含两个有限非布尔数的 JSON 数组（tuple 解码后重建）、`context` 是非空字符串；它不校验 MAC。

`attest_observation_for_point(id, x, y, decision, point, context, issued_at, key)` 用非空 `key` 签名一条绑定点与用途的观察（`version` 固定为 1），字段违约或空 key 均抛 `ValueError`；纯计算，不触碰任何验证者状态。

`locate_bound_attested(observations, point, context, keys, *, quorum=3, tolerance=0.0, now=None, max_age=None, revocations=None) -> Consensus` 的对象/字节混输、`keys` 映射、恒时验签、重复 id、时效（`now`/`max_age`）、撤销、几何与 quorum 规则与 `locate_attested` **完全一致**（未达 quorum 同样不抛异常），在此之上增加绑定校验：每条记录 MAC 验证通过后，其 `point` 必须与查询 `point` **逐项相等**、其 `context` 必须与查询 `context` **精确相等**，否则抛 `ValueError`——绑定其他点或其他用途的签名不能拿到本次查询重放。查询参数本身也受契约约束：`point` 必须是恰含两个非布尔有限数的 tuple，`context` 必须是非空字符串。契约违约抛 `ValueError`；调用形状错误（缺参数、关键字选项按位置传入等）抛 `TypeError`。

```python
from nearproof import RangeDecision, attest_observation_for_point, locate_bound_attested

context = "room-7"
records = [
    attest_observation_for_point("alpha", 0.0, 0.0, RangeDecision(5, 5.0, True), (0.0, 0.0), context, now, keys["alpha"]),
    attest_observation_for_point("bravo", 3.0, 0.0, RangeDecision(5, 5.0, False), (0.0, 0.0), context, now, keys["bravo"]),
    attest_observation_for_point("charlie", 0.0, 4.0, RangeDecision(5, 5.0, True), (0.0, 0.0), context, now, keys["charlie"]),
]
consensus = locate_bound_attested(records, (0.0, 0.0), context, keys, max_age=60.0)
consensus.accepted                     # True
# locate_bound_attested(records, (1.0, 0.0), context, keys) -> ValueError（点不逐项相等）
# locate_bound_attested(records, (0.0, 0.0), "room-8", keys) -> ValueError（用途不符）
```

### 观察撤销 `ObservationRevocation` 与 `revoke_observation`

`ObservationRevocation(version, id, revoked_at, mac)` 是冻结的带签名撤销记录，构造时即校验全部字段契约，任何违约抛 `ValueError`：`version` 必须为 `1`；`id` 为非空字符串；`revoked_at` 为非布尔、有限、非负的数；`mac` 为恰好 32 字节的 `bytes`。`mac` 是共享密钥对“规范编码的无 mac 对象”（`version, id, revoked_at`）的 HMAC-SHA256，记录本身不含密钥。

`to_bytes()` 按无空白 UTF-8 JSON 编码：键依字段顺序（`version, id, revoked_at, mac`），`mac` 为小写十六进制。`from_bytes(data)` 的编解码与 MAC 规则和 `AttestedObservation` 相同：键必须恰好是四个字段、各出现一次且依字段顺序，解析与字段校验后按规范重编码并与输入逐字节比较，任何格式化 JSON、空白或非规范写法均抛 `ValueError`；它不校验 MAC。

`revoke_observation(id, revoked_at, key)` 用非空 `key` 签发一条撤销记录（`version` 固定为 1），字段违约或空 key 均抛 `ValueError`；签发是纯计算，不触碰任何验证者状态。签发的记录（或其字节编码）通过 `locate_attested(..., revocations=...)` 传入后生效，语义见上节。

```python
import time

from nearproof import revoke_observation

revocation = revoke_observation("alpha", time.time(), keys["alpha"])
blob = revocation.to_bytes()           # 可持久化或传输
# locate_attested(observations, point, keys, revocations=[blob], now=time.time())
```

## 限制

当前是单验证者的朴素往返测距：挑战先发出、应答后到达，两者之间没有任何延迟承诺，应答正确性也不绑定到挑战发出时刻（配置 `challenge_ttl_seconds` 后仅按验证者时钟限制挑战本身的有效期，并不约束证明者的应答时刻）。单轮距离直接由一次往返时间换算；跨轮的稳健判定由 `assess` 在事后基于中位数 / MAD 离群点剔除完成，它不改变单轮验证语义，也不提供多轮间的密码学一致性。默认模式下 nonce 只保证随机，不记录已用集合；开启 `replay_protection` 后则按签发实例登记并追踪每个挑战的待验证 / 已消费 / 已撤销 / 已过期状态，但注册表（含截止时刻）仅保存在内存中、随实例生命周期结束，过期判定也完全信任注入的 `clock`。二维共识 `locate` 只把各验证者 `assess` 出的距离上界按圆盘覆盖做纯几何聚合：它不交叉验证观察来源、不绑定验证者身份与坐标的真实性，圆盘矛盾只表现为拒绝计数而非异常。`locate_attested` 在此之上为每条观察加了 HMAC 签名复核与可选的时效检查，但它完全信任调用方给出的 `keys` 映射（id 与密钥、坐标的绑定由调用方保证），时效判定也完全信任注入的 `now` 或系统时钟；签名不绑定候选点，同一条记录可被拿到任意点上重放聚合。`locate_bound_attested` 用的 `BoundAttestedObservation` 把候选点与用途串也纳入 MAC，并要求与查询值逐项/精确相等，因此不能跨点或跨用途重放，但仍完全信任调用方提供的 `keys`、`now` 与点/用途串本身的真实性。

## 测试

```bash
python3 -m unittest discover -s tests
```
