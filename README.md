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
- `Prover(shared_key)` — `respond(challenge) -> bytes`（HMAC-SHA256 应答）；`reveal(challenge, context, opening) -> bytes` 用于上下文绑定轮次（见下）；`bit(t, d, i, b) -> bytes` 用于位挑战轮次（`t` 16 字节、`d` 32 字节、`i` 非布尔 u32、`b` 仅 0/1；见下）
- `RangeDecision(sample_count, upper_bound, accepted)` — `assess` 的冻结结果：`sample_count` 统计全部输入样本（含离群点），`upper_bound` 为内点最大距离，`accepted` 表示其不超过 limit
- `Verifier(shared_key, *, speed_mps=SPEED_OF_LIGHT_MPS, clock=time.perf_counter, replay_protection=False, challenge_ttl_seconds=None)`
  - `new_challenge(*, context=None, digest=None)` — 默认（均为 `None`）生成 16 字节随机 nonce，行为与旧版一致；成对传入 32 字节 `context`/`digest` 则签发上下文绑定挑战（要求 `replay_protection=True`，只传一个抛 `ValueError`）；配置有效期时按 `clock()` 记录签发时刻
  - `verify(challenge, response, started_at, *, opening=None) -> Measurement` — 校验应答并把往返时间折半换算为距离；`opening=None` 为旧行为，传入 32 字节 `opening` 则走上下文绑定协议（见下）
  - `verify_evidence(challenge, response, started_at)` — 同 `verify` 的参数与语义，成功时返回 `Evidence`
  - `verify_bound(challenge, response, started_at, *, opening) -> BoundEvidence` — 仅限上下文绑定挑战的 `verify_evidence`（见下）
  - `measure(prover)` — 一次完整往返
  - `bits(prover, context, opening, *, rounds=32, timeout=0.001) -> bytes` — 跑一场位挑战会话，返回 `BitEvidence.to_bytes()` 的字节证据；`context`/`opening` 各 32 字节（见下）
  - `start_bits(context, opening, *, rounds=32, timeout=0.001) -> BitSession` — 开始一场**步进驱动**的位挑战会话（同 `bits` 参数契约）；`BitSession.next() -> BitRound` 发一轮、`submit(round, response)` 交应答、`finish() -> bytes` 产出与 `bits` 相同的 `BitEvidence` 字节、`revoke()` 放弃
  - `resume_bits(x, *, floor=None) -> BitSession` — 从冻结的 `BitState`（对象或规范字节）验签并恢复一场**活动**位会话；`floor` 可收上一次接受的 `BitState`/字节或 `None`，做低序/同序/高序门控（见下）
  - `revoke(challenge)` — 显式撤销一个仍待验证的挑战（仅在 `replay_protection=True` 时可用）
  - `clock` — 只读属性，暴露计时函数
- `assess(samples, limit, *, key=None, min_samples=5) -> RangeDecision` — 基于一批轮次的稳健距离判定（见下）
- `audit(evidence, key)` — 用共享密钥复核 `Evidence`（或其字节编码），返回对应的 `Measurement`
- `BitEvidence(version, t, context, digest, opening, queries, speed, timeout, limit, mac)` — 一场已接受**位挑战**会话的防篡改记录（`version=1`；`t` 恰 16 字节，`context`/`opening`/`digest`/`mac` 各恰 32 字节，`queries` 非空、每项为 `(b, r, s, e)`；不含密钥；见下）
  - `to_bytes()` — 无空白 UTF-8 JSON **数组**，字段序 `[1, t, C, D, O, Q, V, T, L, M]`，bytes 字段小写 hex
  - `from_bytes(data)` — 按字段契约解码并重编码逐字节比对，非 bytes 或不合契约一律抛 `ValueError`（不校验 MAC）
- `audit_b(x, k) -> float` — **仅收非空 bytes** 的证据字节与非空 bytes 密钥；恒时复核 `NPFB1` MAC，重算 `D`、逐位应答（按下标 i）、`0 <= e-s <= T` 与 `L = max(e-s)*V/2`，任何不符抛 `ValueError`，成功返回复算的 `L`（见下）
- `BitState(version, seq, body, mac)` — 一场**进行中**步进位会话的冻结检查点（`version=1`、`seq` 为非布尔 u64 且等于 body 中 `Q` 项数；`body` 为内层紧凑 JSON 字节、`mac` 恰 32 字节；按字段序位置构造、冻结、按字段相等；错型 `TypeError`、余错 `ValueError`；不含密钥；见下）
  - `to_bytes()` / `from_bytes(data)` — 内外两层均为紧凑 UTF-8 JSON 且规范往返：外层字段序四元数组 `[1, seq, body, mac]`，`body`/`mac` 小写 hex；body 解码为 `[t, C, D, O, R, T, V, Q, P]`；`from_bytes` 非 bytes 或内层字段错型抛 `TypeError`，其余不合契约（含非规范拼写）抛 `ValueError`，均不验 MAC
- `BitFrontier(version, seq, digest, mac)` — 位会话持久化**防回滚前沿**（`version=1`、`seq` 为非布尔 u64、`digest=SHA256(x.body)`、`digest`/`mac` 各恰 32 字节；`mac=HMAC-SHA256(key, b"NPBF1"+去mac规范JSON)`，各段直拼无长度前缀；按字段序位置构造、冻结、按字段相等；字段错型抛 `TypeError`，余错抛 `ValueError`；不含密钥）
  - `to_bytes()` / `from_bytes(data)` — 紧凑 UTF-8 JSON **对象**，键依字段顺序 `version, seq, digest, mac` 且各出现一次（缺、多、重复、乱序即拒绝），`digest`/`mac` 小写 hex；`from_bytes` 非 bytes 或字段错型抛 `TypeError`，其余不合契约（含重编码非逐字节相等）抛 `ValueError`，不验 MAC
- `BitGuard(verifier, *, checkpoint=None)` — 带状态、防回滚的位会话恢复门；`verifier` 必须是 `Verifier`（错型 `TypeError`），用其共享密钥恒时验证 MAC；`checkpoint` 收 `BitFrontier`、规范 bytes 或 `None`（种类错 `TypeError`、内容违约/MAC 不符 `ValueError`），重启时须由调用方传回保存的最新前沿
  - `resume(x) -> BitSession` — `x` 收 `BitState` 或规范 bytes（错型 `TypeError`），先复用 `resume_bits` 校验恢复，再在锁内以 `seq` 与 `SHA256(body)` 门控：低序拒绝、同序仅同摘要重放、高序推进为新 MAC 前沿；验签、门控与更新锁内原子，失败不改状态
  - 只读 `checkpoint` 属性导出当前 `BitFrontier | None`（首次成功恢复前为 `None`）
- `BoundEvidence(version, evidence, context, digest, opening, mac)` — 一轮已接受**上下文绑定**验证的防篡改记录（`version=1`，四个 bytes 字段均恰 32 字节，不含密钥；见下）
  - `to_bytes()` — 无空白 UTF-8 JSON 编码：键依字段顺序，`evidence` 为规范嵌套对象，bytes 字段为小写十六进制
  - `from_bytes(data)` — 按字段契约解码并重编码逐字节比对，非 bytes 或不合契约一律抛 `ValueError`（不校验 MAC）
- `audit_bound(bound, key)` — 用共享密钥复核 `BoundEvidence`（或其字节编码），返回对应的 `Measurement`
- `audit_bound_policy(bound, key, *, now=None, max_age=None, revocations=None) -> Measurement` — 先按 `audit_bound` 复核，再可选做时效/撤销复核（见下）
- `BoundEvidenceRevocation(version, round_index, nonce, revoked_at, mac)` — 带 HMAC 签名的冻结绑定证据撤销记录（`version=1`，`round_index` 为非布尔 u64，`nonce` 恰 16 字节，`mac` 恰 32 字节，不含密钥；见下）
  - `to_bytes()` — 无空白 UTF-8 JSON 编码：键依字段顺序，`nonce`/`mac` 为小写十六进制
  - `from_bytes(data)` — 按字段契约解码并重编码逐字节比对，非 bytes 或不合契约一律抛 `ValueError`（不校验 MAC）；`revoked_at` 保留解析类型：JSON 整数仍为 `int`、浮点仍为 `float`，两种写法均可往返
- `revoke_bound(bound, revoked_at, key) -> BoundEvidenceRevocation` — 用非空 key 对一条 `BoundEvidence`（或其字节编码）签发撤销记录（见下）
- `ContextRevocation(version, context, revoked_at, mac)` — 带 HMAC 签名的冻结**上下文批量**撤销记录（`version=1`，`context`/`mac` 各恰 32 字节，`revoked_at` 存为 `float`，不含密钥；见下）；字段类型错（形状错）抛 `TypeError`，值违约抛 `ValueError`
  - `to_bytes()` — 无空白 UTF-8 JSON 编码：键依字段顺序，`context`/`mac` 为小写十六进制，无长度前缀
  - `from_bytes(data)` — 按字段契约解码并重编码逐字节比对（不校验 MAC）：非 bytes 或字段类型错抛 `TypeError`，其余不合契约一律抛 `ValueError`
- `revoke_context(context, revoked_at, key) -> ContextRevocation` — 用非空 key 对一个 32 字节 context 签发批量撤销记录（见下）
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
- `VerifierTrust(version, id, x, y, key, mac)` — 根密钥 MAC 的冻结信任记录，把验证者 id 绑定到其坐标与共享密钥（`version=1`，`key`/`mac` 各恰 32 字节，不含根密钥；见下）
  - `to_bytes()` — 无空白 UTF-8 JSON 编码：键依字段顺序，`key`/`mac` 为小写十六进制
  - `from_bytes(data)` — 按字段契约解码并重编码逐字节比对，非 bytes 或不合契约一律抛 `ValueError`（不校验 MAC）
- `cert(id, x, y, key, root) -> VerifierTrust` — 用非空 root bytes 签发信任记录：`mac = HMAC-SHA256(root, b"NPVT1" + 去mac编码)`，两段直接拼接、无长度前缀（见下）
- `locate_cert(records, point, context, trusts, root, *, revocations=None, now=None, min=0) -> Consensus` — 以根证书信任链验签既有绑定观察，`quorum` 固定 3、`tolerance` 固定 0.0；可选传入单证书永久撤销列表（旧形式：`TrustRevocation` 对象/字节的可迭代对象）或一个签名的全局撤销快照 `TrustRevocationList`（对象或字节，需同时给 `now`，经 `audit_crl` 审核；见下）
- `TrustRevocation(version, id, target, mac)` — 根密钥 MAC 的冻结单证书永久撤销记录（`version=1`，`id` 为非空 str，`target`/`mac` 各恰 32 字节，不含根密钥；见下）；字段类型错（形状错）抛 `TypeError`，值违约抛 `ValueError`
  - `to_bytes()` — 无空白 UTF-8 JSON 编码：键依字段顺序，`target`/`mac` 为小写十六进制，无长度前缀
  - `from_bytes(data)` — 按字段契约解码并重编码逐字节比对（不校验 MAC）：仅收 `bytes`，非 bytes 或字段类型错抛 `TypeError`，其余不合契约一律抛 `ValueError`
- `revoke_trust(trust, root) -> TrustRevocation` — 仅收 `VerifierTrust` 与非空 root bytes，对该证书签发永久撤销：`mac = HMAC-SHA256(root, b"NPVR1" + 去mac规范JSON)`，两段直接拼接、无长度前缀（见下）
- `TrustRevocationList(version, sequence, issued_at, entries, mac)` — 根密钥 MAC 的冻结全局撤销快照（`version=1`，`sequence` 为非布尔 u64，`issued_at` 存为 `float`，`entries` 为按 `(id, target)` 升序且无重复的 `TrustRevocation` 元组，`mac` 恰 32 字节；见下）；违约一律抛 `ValueError`
  - `to_bytes()` — 字段序紧凑 UTF-8 JSON：`entries` 为对象数组（每条带自己的 `mac`），外层最后一个键是列表 `mac`（小写十六进制），无空白、无长度前缀
  - `from_bytes(data)` — 仅收 `bytes`（否则 `TypeError`）；缺/多/重复/乱序键、entries 不是数组、某条 entry 不合 `TrustRevocation` 契约、u64/float-u64 等字段违约、编码非规范均抛 `ValueError`；成功返回本类且不验任何 MAC
- `make_crl(items, seq, time, root) -> TrustRevocationList` — 用与签证书相同的 root bytes 对一批 `TrustRevocation`（可为空；不接受字节）签快照：先按 `(id, target)` 排序、重复对抛 `ValueError`，`mac = HMAC-SHA256(root, b"NPVRL1" + 去mac规范JSON)`，直拼无长度前缀；`root` 非 bytes 抛 `TypeError`、空 bytes 抛 `ValueError`
- `audit_crl(x, root, now, min=0) -> None` — 收快照对象或字节；恒时复核双层 MAC（列表层 `NPVRL1`、每条 entry 的 `NPVR1`，同一 root），并检查 `issued_at <= now`、`sequence >= min`；对象/root 形状错抛 `TypeError`，其余（含 MAC 不符、未来时间、序号过低）一律抛 `ValueError`
- `CertifiedConsensusEvidence(version, body, mac)` — 根密钥 MAC 的冻结共识证据（`version=1`；`body` 为 bytes，`mac` 恰 32 字节 bytes，否则 `ValueError`；见下）；按字段序位置构造、冻结且按字段相等
  - `to_bytes()` — 外层紧凑 UTF-8 JSON：键序固定 `version, body, mac`，`body`/`mac` 为小写十六进制；构造器对 `body` 内容不透明，但 `to_bytes()` 会把 `body` 解码后用规范编码器重编码并与原字节逐字节比对，不一致（非 JSON、空白、非规范拼写）抛 `ValueError`，且不改写已冻结的 `body`
  - `from_bytes(data)` — 双层均按紧凑 UTF-8 JSON 校验并重编码逐字节比对；非 bytes 或任一层不合契约一律抛 `ValueError`（不验 MAC）
- `locate_cert_evidence(records, point, context, trusts, root) -> CertifiedConsensusEvidence` — 跑一次 `locate_cert`（无撤销选项）并把结果与参与项封进证据；参与记录按 id 排序、信任按 id 同序对齐，均为规范字节编码的小写十六进制（见下）
- `audit_cert_evidence(x, root) -> Consensus` — 收证据对象或字节；恒时验证 `HMAC-SHA256(root, b"NPCCE1" + body)`，再用 body 内的参与项重跑 `locate_cert`，重算 `Consensus` 与 body 所载逐字段相等，否则抛 `ValueError`；成功返回重算的 `Consensus`
- `CrlProof(version, body, mac)` — 根密钥 MAC 的冻结 CRL 快照证明（`version=1`；`body` 为 bytes，`mac` 恰 32 字节 bytes，否则 `ValueError`；按字段序位置构造、冻结且按字段相等）
  - `to_bytes()` — 外层键序固定 `version, body, mac`，`body`/`mac` 为小写十六进制，双层紧凑 UTF-8 JSON 无空白；与 `CertifiedConsensusEvidence` 一样，`body` 规范重编码须与原字节逐字节相等，否则抛 `ValueError` 且不改写
  - `from_bytes(data)` — 非 bytes 或任一层不合契约一律抛 `ValueError`（不验 MAC）；外层须恰为 `version, body, mac`；body 解码为数组 `[point, context, records, trusts, crl, now, min, consensus]`：`point` 为两个有限非布尔数的数组、`context` 为非空字符串、`records`/`trusts` 为规范小写 hex 数组（参与项 id 升序、按 id 一一对应）、`crl` 为规范 `TrustRevocationList` 字节的小写 hex、`now` 为有限非布尔数、`min` 为非布尔整数、`consensus` 为 `[total, support, rejected, accepted]`（`rejected` 按字典序）
- `prove_crl(records, point, context, trusts, root, crl, *, now, min=0) -> CrlProof` — 按 `locate_cert` 的签名快照路径（`revocations=crl`、`now` 必填、`min` 默认 `0`，均仅限关键字）求共识并把参与项封进证明；`crl` 收 `TrustRevocationList` 对象或规范字节；参与记录按 id 升序、信任按 id 同序对齐，`crl`/记录/信任均为规范字节的小写 hex；`mac = HMAC-SHA256(root, b"NPCCE2" + body)`，直拼无定界/长度前缀；`root` 非 bytes 抛 `TypeError`、空 bytes 及其他违约抛 `ValueError`
- `audit_proof(x, root) -> Consensus` — 收 `CrlProof` 对象或规范字节；恒时验证 `HMAC-SHA256(root, b"NPCCE2" + body)`，再按 body 重放 `audit_crl`（双层 MAC、`issued_at <= now`、`sequence >= min`）和 `locate_cert` 快照路径，重算 `Consensus` 与 body 所载逐字段相等；`root` 类型错抛 `TypeError`（空 bytes 抛 `ValueError`），其余错误（含重放中冒出的 `TypeError`）一律抛 `ValueError`；成功返回重算的 `Consensus`
- `CrlState(version, sequence, digest, mac)` — 防回滚的冻结 CRL 前沿检查点（`version=1`、`sequence` 为非布尔 u64、`digest`/`mac` 各恰 32 字节；`digest=SHA256(证明内规范 CRL 字节)`、`mac=HMAC-SHA256(root, b"NPCK1"+去mac规范编码)`，直拼无长度前缀；违约抛 `ValueError`）
  - `to_bytes()` / `from_bytes(data)` — 紧凑 UTF-8 JSON（键序 `version, sequence, digest, mac`，bytes 字段小写 hex）；`from_bytes` 仅收 `bytes`、重编码须逐字节相等，不验 MAC
- `CrlProofAuditor(root, *, checkpoint=None)` — 带状态、防回滚的证明审计器；`root` 为非空 `bytes`（类型错抛 `TypeError`，空值抛 `ValueError`）；`checkpoint` 收 `CrlState` 或其规范字节并恒时验 MAC（`None` 为空状态），重启时须由调用方传回保存的最新检查点
  - `audit(proof) -> Consensus` — 先跑无状态 `audit_proof`，再在锁内取证明所载 CRL 的序号与规范字节哈希做门控：低序拒绝、同序仅同哈希重放、高序推进；比较与更新锁内原子，失败不改状态，并发绝不回退
  - 只读 `checkpoint` 属性导出当前 `CrlState | None`
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

`audit_bound_policy(bound, key, *, now=None, max_age=None, revocations=None)` 在 `audit_bound` 的全部密码学、规范编码与测距复核（及其 `ValueError` 语义）完全不变的基础上，增加可选的时效与撤销复核：`max_age=None` 且 `revocations=None`（均为默认）时不做任何额外检查——`now` 被完全忽略且不读取任何时钟。

- `max_age` 启用时必须是非布尔、有限、非负的数，以已审计的 `bound.evidence.end` 为签发完成时刻，必须满足闭区间 `0 <= now - end <= max_age`——未来或超龄证据抛 `ValueError`，两端边界相等均有效。
- `revocations` 启用时必须是可迭代对象，可混用 `BoundEvidenceRevocation`、`ContextRevocation` 对象与它们的规范字节编码：每条撤销用同一 `key` **恒时**复核 MAC，非法项、重复的 `(round_index, nonce)` 对、重复的 `context`、错误 key 或篡改一律抛 `ValueError`；`revoked_at > now` 的“未来撤销”抛 `ValueError`。`BoundEvidenceRevocation` 在其 `round_index`/`nonce` 与本证据嵌套 `Evidence` 完全相同时命中，`ContextRevocation` 在其 `context` 与本证据的 `context` 相等时命中；命中且 `end <= revoked_at` 时抛 `ValueError`（同类去重保证每类至多一条命中），不命中的撤销在 MAC 与时间检查之外被忽略；完成时刻严格晚于撤销时刻的证据不受影响，再走时效检查。
- 任一检查启用时 `now` 为必传的非布尔有限数（不提供或违约均抛 `ValueError`）。

与 `audit_bound` 一样，它是纯函数：不触碰任何验证者状态与挑战生命周期。

```python
challenge = verifier.new_challenge(context=context, digest=digest)
response = prover.reveal(challenge, context, opening)
bound = verifier.verify_bound(challenge, response, verifier.clock(), opening=opening)
blob = bound.to_bytes()                          # 可持久化或传输
measurement = audit_bound(BoundEvidence.from_bytes(blob), key)
```

### 绑定证据撤销 `BoundEvidenceRevocation` 与 `revoke_bound`

`BoundEvidenceRevocation(version, round_index, nonce, revoked_at, mac)` 是冻结的带签名绑定证据撤销记录，构造时即校验全部字段契约，任何违约抛 `ValueError`：`version` 必须为 `1`；`round_index` 为非布尔、取值于 `[0, 2^64-1]` 的整数；`nonce` 为恰好 16 字节的 `bytes`；`revoked_at` 为非布尔、有限、非负的数；`mac` 为恰好 32 字节的 `bytes`。`round_index`/`nonce` 共同标识被撤销的那轮 `BoundEvidence`（即其嵌套 `Evidence` 的同名字段）。`mac = HMAC-SHA256(key, b"NPBR1" + 去 mac 规范 JSON)`，记录本身不含密钥。

`to_bytes()` 按无空白 UTF-8 JSON 编码：键依字段顺序（`version, round_index, nonce, revoked_at, mac`），`nonce`/`mac` 为小写十六进制，无长度前缀。`from_bytes(data)` 要求键恰好是五个字段、各出现一次且依字段顺序，`round_index` 为非布尔 u64，`nonce` 解码后恰 16 字节，`revoked_at` 有限非负，`mac` 解码后恰 32 字节；`revoked_at` **保留解析类型**——JSON 整数仍为 `int`、JSON 浮点仍为 `float`，因此 `3` 与 `3.0` 两种写法都能通过规范重编码逐字节比对；解析与字段校验后按规范重编码并与输入逐字节比较，任何格式化 JSON、空白或非规范写法（如 `3.00`）均抛 `ValueError`；它不校验 MAC。

`revoke_bound(bound, revoked_at, key)` 接受 `BoundEvidence` 或其字节编码，用非空 `key` 签发一条撤销记录（`version` 固定为 `1`，`round_index`/`nonce` 取自其嵌套证据）；字段违约或空 key 均抛 `ValueError`；签发是纯计算，不触碰任何验证者状态。签发的记录（或其字节编码）通过 `audit_bound_policy(..., revocations=...)` 传入后生效，语义见上节。

```python
from nearproof import revoke_bound

revocation = revoke_bound(bound, time.time(), key)
blob = revocation.to_bytes()                     # 可持久化或传输
# audit_bound_policy(bound, key, now=time.time(), revocations=[blob])
```

### 上下文批量撤销 `ContextRevocation` 与 `revoke_context`

`ContextRevocation(version, context, revoked_at, mac)` 是冻结的带签名**批量**撤销记录：一条记录撤销同一 32 字节 `context` 下的全部绑定证据。字段类型依次为 `int`/`bytes`/`float`/`bytes`；构造时即校验全部字段契约——**形状错（字段类型不对）抛 `TypeError`，值违约抛 `ValueError`**：`version` 必须为 `1`；`context` 为恰好 32 字节的 `bytes`；`revoked_at` 为非布尔、有限、非负的数并**存为 `float`**；`mac` 为恰好 32 字节的 `bytes`。`mac = HMAC-SHA256(key, b"NPCR1" + 去 mac 规范 JSON)`，记录本身不含密钥。

`to_bytes()` 按无空白 UTF-8 JSON 编码：键依字段顺序（`version, context, revoked_at, mac`），`context`/`mac` 为小写十六进制，无长度前缀。`from_bytes(data)` 要求键恰好是四个字段、各出现一次且依字段顺序，`context`/`mac` 为解码后恰 32 字节的小写十六进制，`revoked_at` 有限非负；解析与字段校验后按规范重编码并与输入逐字节比较（`revoked_at` 存为 `float`，故只有浮点写法 `3.0` 能往返，整数写法 `3` 重编码不等而被拒）。非 bytes 输入或字段类型错抛 `TypeError`，其余不合契约（含格式化 JSON、空白、非规范写法）一律抛 `ValueError`；它不校验 MAC。

`revoke_context(context, revoked_at, key)` 用非空 `key` 对一个 32 字节 `context` 签发批量撤销记录（`version` 固定为 1）；空 key 或字段值违约抛 `ValueError`，字段形状错抛 `TypeError`；签发是纯计算，不触碰任何验证者状态。签发的记录（或其字节编码）通过 `audit_bound_policy(..., revocations=...)` 传入后生效，可与 `BoundEvidenceRevocation` 混用，语义见上文 `audit_bound_policy` 一节。

```python
from nearproof import revoke_context

revocation = revoke_context(context, time.time(), key)
blob = revocation.to_bytes()                     # 可持久化或传输
# audit_bound_policy(bound, key, now=time.time(), revocations=[blob])
```

### 位挑战会话 `Prover.bit`、`Verifier.bits` 与 `audit_b`

位挑战把一次距离边界证明冻结成一份自证字节记录。证明者侧只有一个新应答：`Prover.bit(t, d, i, b) -> bytes`，其中 `t` 必须恰 16 字节、`d` 恰 32 字节、`i` 为非布尔无符号 32 位整数（`0 .. 2^32-1`）、`b` 只能是整数 `0` 或 `1`（`bool`、浮点、其他取值一律 `ValueError`），返回

```
r = HMAC-SHA256(key, b"NPFR1" + t + u32be(i) + bytes([b]) + d)
```

`u32be` 为 4 字节大端无符号整数，各段直拼无长度前缀。

`Verifier.bits(prover, context, opening, *, rounds=32, timeout=0.001) -> bytes` 跑一场会话并直接返回证据字节，**旧接口不变**：

- `context`/`opening` 各须恰 32 字节 bytes；`rounds` 为 `1 .. 2^32` 的非布尔整数；`timeout` 为有限正的非布尔数（`bool`、0、负数、`inf`、`nan` 均拒）；
- 会话开始生成随机 16 字节 `t`，计算 `D = SHA256(b"NPFC1" + C + O)`（C/O 即 context/opening）；
- 每轮 `j` 随机抽取一个挑战位 `b`，先读时钟得 `s`，调用 `prover.bit(t, D, j, b)`（调用参数中的下标就是轮次下标，从 0 起），再读时钟得 `e`；对返回值恒时比对
  `HMAC-SHA256(key, b"NPFR1" + t + u32be(j) + bytes([b]) + D)`，非恰 32 字节或不符即 `ValueError`；
- 每轮往返 `R = e - s` 必须满足闭区间 `0 <= R <= T`（`T = float(timeout)`，两端边界相等均有效）；负耗时、超时、非有限时钟读数均 `ValueError`；
- 距离上界 `L = max(R) * V / 2`，`V` 为该验证者的传播速度；`V`/`s`/`e`/`L` 均为有限 float，`L >= 0`。

`prover` 只需提供可调用的 `bit(t, d, i, b)`（鸭子类型）；无可调用 `bit`、调用签名不符或应答错误一律 `ValueError`。

证据为紧凑 UTF-8 JSON **数组**（沿用 Evidence 编码规范：无空白、bytes 为小写 hex、不允许 NaN/Infinity）：

```
A = [1, t, C, D, O, Q, V, T, L, M]
Q = [[b, r, s, e], ...]          # 第 j 项的下标即 i = j，r 为小写 hex
M = HMAC-SHA256(k, b"NPFB1" + E) # E = 去掉 M 的同一数组
```

`BitEvidence` 是该数组的冻结记录（按字段序位置构造、按字段相等），`to_bytes()` 产出现范字节；`from_bytes(data)` 仅收 bytes，要求恰为十个元素的数组、键位字段契约全部满足（`version==1`、各 bytes 字段长度、`b∈{0,1}` 且非 bool、数值有限非布尔、`T>0`、`L>=0`、`Q` 非空），并把解析结果重编码与输入**逐字节**比对——格式化 JSON、空白、整数时钟字面量等非规范写法一律 `ValueError`；它不校验 MAC。

`audit_b(x, k) -> float` 的 `x`（证据）与 `k`（密钥）**都只收非空 bytes**：对象、`bytearray`、`str`、空值或其他类型一律 `ValueError`。它用 `k` 恒时复核 `NPFB1` MAC，再由原始字段重算全部各式：`D = SHA256(b"NPFC1"+C+O)`、每项在其下标 `i` 处的应答 `r`、闭区间 `0 <= e-s <= T`，以及 `L = max(e-s)*V/2`；任一处不符抛 `ValueError`，全部通过则返回复算的 `L`。审计是纯函数，不触碰任何验证者状态。

```python
from nearproof import Prover, Verifier, audit_b

prover, verifier = Prover(key), Verifier(key)
blob = verifier.bits(prover, context, opening, rounds=32, timeout=0.001)
upper_bound = audit_b(blob, key)          # 复算通过则返回 L（米）
```

### 会话冻结与恢复 `BitSession.checkpoint`、`BitState` 与 `Verifier.resume_bits`

步进会话（`start_bits`）可以在任意**活动**时刻冻结成自证检查点，落到另一进程/验证者后继续跑完：

- `BitSession.checkpoint() -> bytes` **仅活动态可用**：已 `finish()` 或 `revoke()` 的会话调用抛 `ValueError`；取检查点不推进会话（待决轮次保持待决，可再次 `checkpoint` 得到逐字节相同的结果）。
- 冻结记录为 `BitState(version, seq, body, mac)`：按字段序位置构造、冻结、按字段相等；字段错型抛 `TypeError`，其余违约抛 `ValueError`。
  - `version=1`；`seq` 为非布尔 u64，且恒等于 body 中 `Q` 的项数；
  - `body` 解码为数组 `[t, C, D, O, R, T, V, Q, P]`：`t`/`C`/`D`/`O` 同既有位协议（16/32/32/32 字节小写 hex）；`R` 为 `1 .. 2**32` 的非布尔整数（总轮数）；`T`/`V` 为有限正的非布尔数；`Q` 项为 `[b, r, s, e]`，字段同位证据（`b∈{0,1}` 非布尔、`r` 为 32 字节小写 hex、`s`/`e` 有限非布尔），且 `0 <= seq = len(Q) <= R`；`P` 为 `null` 或 `[seq, b, s]`，后者的 `seq` 须满足 `0 <= seq < R`，描述取检查点时仍待决的那一轮（无待决轮时为 `null`）；
  - `mac = HMAC-SHA256(key, b"NPBS1" + E)`，`E` 是外层去掉 `mac` 的字段序数组 `[1, seq, body_hex]` 用同一紧凑法编码，前缀直拼无分隔/长度前缀。
  - `to_bytes()`/`from_bytes(data)` 内外两层都是紧凑 UTF-8 JSON 并做规范往返：外层为 `[1, seq, body, mac]` 四元数组、`body`/`mac` 小写 hex；内层 body 重编码（数值按 float 拼写）须与原字节逐字节相等——整数时钟字面量、空白、格式化 JSON 等均拒绝。`from_bytes` 仅收 bytes（非 bytes 抛 `TypeError`），内层字段错型也抛 `TypeError`，其余（含非规范）抛 `ValueError`；它不验 MAC。

恢复入口为 `Verifier.resume_bits(x, *, floor=None) -> BitSession`：

- `x` 与 `floor` 仅收 `BitState` 对象或其规范 bytes，`floor` 还可为 `None`（默认）；参数种类不对（`str`、`bytearray`、`None` 给 `x` 等）抛 `TypeError`，bytes 内容不合契约抛 `ValueError`。
- 先恒时验证 `NPBS1` MAC，再由原始字段重算并核对：`D = SHA256(b"NPFC1"+C+O)`、每项按下标 `i` 的 `NPFR1` 应答、闭区间 `0 <= e-s <= T`，以及待决轮 `P` 的下标恰为 `len(Q)`；任一不符抛 `ValueError`。
- 恢复出的会话为**活动态**，沿用检查点自带的 `V`/`T`/`C`/`O`/`t` 与已完成的 `Q`，但使用**当前验证者**的时钟；有 `P` 时该轮仍待决（先 `submit` 再 `next`），无 `P` 时从 `len(Q)` 续发；随后 `next`/`submit`/`finish`/`revoke` 语义全新会话，`finish` 产出与一次跑完完全相同的 `BitEvidence`。
- `floor` 为调用方上次接受的检查点时做单调门控：**低序拒绝**；**同序**仅当两份 `SHA256(body)` 完全相同才作为重放接受；**高序**要求前七项（`t, C, D, O, R, T, V`）逐项相同、`Q` 逐项延续 floor 的 `Q` 前缀；floor 的 `P` 有值时，新状态中下一个 `Q` 项必须承接其待决轮的 `b` 与 `s`（即该轮已被完成且起点/挑战位未变）。门控不改变任何状态，失败即 `ValueError`。旧接口（`bits`/`start_bits`/`audit_b` 等）保持不变。

```python
session = verifier.start_bits(context, opening, rounds=32, timeout=0.001)
rnd = session.next(); session.submit(rnd, prover.bit(rnd.t, D, rnd.index, rnd.bit))
saved = session.checkpoint()                 # 活动态随时冻结（BitState bytes）
# ... 另一个进程、同一个 key 的验证者 ...
session2 = verifier2.resume_bits(saved, floor=last_accepted)
rnd = session2.next(); session2.submit(rnd, prover.bit(rnd.t, D, rnd.index, rnd.bit))
blob = session2.finish()                     # 与一次跑完相同的 BitEvidence
```

### 持久化防回滚 `BitFrontier` 与 `BitGuard`

`Verifier.resume_bits(floor=...)` 的单调门控只活在单次调用内；要在进程重启、落盘后仍拒绝回滚的检查点，用冻结的 `BitFrontier` 与带状态的 `BitGuard`：

- 前沿记录为 `BitFrontier(version, seq, digest, mac)`：按字段序位置构造、冻结、按字段相等；字段错型抛 `TypeError`，其余违约抛 `ValueError`。
  - `version=1`；`seq` 为非布尔 u64（接受的 `BitState.seq`）；
  - `digest = SHA256(x.body)`，即被接受检查点内层规范 body 字节的 SHA-256（恰 32 字节）；
  - `mac = HMAC-SHA256(key, b"NPBF1" + J)`，其中 `J` 是去掉 `mac` 的字段序对象 `{"version":1,"seq":...,"digest":...}` 用紧凑 UTF-8 JSON 编码，前缀与 `J` 直接拼接、无分隔/长度前缀；
  - `to_bytes()` 即 `{"version":1,"seq":...,"digest":...,"mac":...}` 的紧凑 JSON（键依字段顺序、bytes 小写 hex、无空白）；`from_bytes(data)` 要求恰好四个键各出现一次且依字段顺序，重编码须与输入逐字节相等，非 bytes/字段错型抛 `TypeError`，其余抛 `ValueError`，且**不验 MAC**。
- `BitGuard(verifier, *, checkpoint=None)` 包住一个 `Verifier` 并持有当前前沿：
  - `verifier` 必须是 `Verifier`（错型 `TypeError`）；前沿 MAC 一律用该验证者的共享密钥；
  - `checkpoint` 仅收 `BitFrontier` 对象、其规范 bytes 或 `None`（默认空状态）；种类错抛 `TypeError`，bytes 内容违约或 MAC 与共享密钥不符恒时比较失败抛 `ValueError`；
  - `resume(x) -> BitSession` 的 `x` 仅收 `BitState` 或规范 bytes（其余 `TypeError`），先复用该验证者的 `resume_bits` 完成 NPBS1 验签与全部重算（失败即 `ValueError`，不动前沿），**再在锁内**门控：低序拒绝、同序仅当 `SHA256(body)` 与前沿摘要完全相同才作为重放接受（不推进）、高序推进为新 `NPBF1` MAC 前沿；验签、门控与更新原子完成，并发恢复绝不回退；
  - 只读 `checkpoint` 属性返回当前 `BitFrontier | None`；落盘其 `to_bytes()` 并在新进程构造 `BitGuard(verifier, checkpoint=...)` 即可跨重启延续门控。旧接口（`bits`/`start_bits`/`resume_bits`/`audit_b` 等）保持不变。

```python
guard = BitGuard(verifier)
restored = guard.resume(session.checkpoint())   # 首次以 (seq, SHA256(body)) 建立前沿
saved_frontier = guard.checkpoint.to_bytes()    # BitFrontier bytes，落盘
# ... 重启、同一个 key 的验证者 ...
guard2 = BitGuard(verifier2, checkpoint=saved_frontier)
guard2.resume(newer_checkpoint)                 # 高序推进；低序/同序异摘要抛 ValueError
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

### 根证书信任 `VerifierTrust`、`cert` 与 `locate_cert`

`VerifierTrust(version, id, x, y, key, mac)` 是根密钥 MAC 的冻结信任记录，把一个验证者 id 绑定到其坐标与共享密钥：按字段序位置构造、冻结且按字段相等；`version` 固定为 `1`；`id` 为非空字符串；`x`/`y` 为非布尔、有限、非负的数；`key` 与 `mac` 各为恰好 32 字节的 `bytes`；任何字段违约在构造时抛 `ValueError`。`mac` 是根密钥对 `b"NPVT1" + 去mac规范编码` 的 HMAC-SHA256——前缀与编码两段直接拼接，无分隔符、无长度前缀；记录本身不含根密钥。

`to_bytes()` 按无空白 UTF-8 JSON 编码：键依字段顺序（`version, id, x, y, key, mac`），`key`/`mac` 为小写十六进制。`from_bytes(data)` 只收 `bytes`：键必须恰好是六个字段、各出现一次且依字段顺序，解析与字段校验后按规范重编码并与输入逐字节相等，否则抛 `ValueError`；它不校验 MAC。

`cert(id, x, y, key, root)` 的 `root` 必须是**非空 `bytes`**：非 bytes（含 `bytearray`、`str`、`None`）抛 `TypeError`，空 bytes 抛 `ValueError`，不做任何隐式转换；其余字段违约抛 `ValueError`；纯计算，不触碰任何验证者状态。

`locate_cert(records, point, context, trusts, root, *, revocations=None, now=None, min=0) -> Consensus` 以根证书信任链复核既有绑定观察（`BoundAttestedObservation` 或其字节编码，混输允许）：`trusts` 同样是对象/字节混输，每个 id 恰有一条，重复 id 抛 `ValueError`；`root` 同样必须是非空 `bytes`（非 bytes 抛 `TypeError`，空 bytes 抛 `ValueError`），每条 trust 的根 MAC 用 `root` 恒时重算比对。随后每条观察记录以其 id 对应证书的 `key` 恒时验 MAC，且证书的 `id`/`x`/`y` 必须与记录相等；缺证书、MAC 不符或坐标不等均抛 `ValueError`。其余规则与 `locate_bound_attested` 相同（点逐项相等、用途精确相等、几何聚合），但 `quorum` 固定为 `3`、`tolerance` 固定为 `0.0`，且不做时效检查；未达 quorum 只体现在结果中，不抛异常。

**逐次撤销列表（旧形式）**：`revocations=None`（默认）或空可迭代对象时不做撤销检查，共识结果与之前完全一致。否则 `revocations` 为可迭代对象，可混用 `TrustRevocation` 对象与其规范字节编码；每条撤销用同一 `root` **恒时**复核根 MAC，非法项、错误 root、篡改一律抛 `ValueError`；两条撤销携带相同 `(id, target)` 对即按重复拒绝。撤销在其 `id` 等于某条**所用证书**的 id 且 `target` 等于该证书的 `mac` 时命中——命中即把该证书永久撤销，凡使用该证书 id 的观察一律抛 `ValueError`；**未命中也一律抛 `ValueError`**（未知 id、同 id 但 target 是另一张证书、或 target 是 `trusts` 中存在但记录未使用的证书，均算未命中）。该形式忽略 `now`/`min`，语义完全不变。

**签名快照（新形式）**：`revocations` 也可以是一个 `TrustRevocationList`（对象或其 `to_bytes()` 字节，见下节）。快照是全局列表，因此与逐次列表不同：快照里与本次证书无关的条目（未知 id、未使用证书）不算违约，只有命中生效。快照先整体经 `audit_crl(revocations, root, now, min=min)` 审核——此形式下 **`now` 必填**（缺省抛 `ValueError`），`min` 为非布尔整数（默认 `0`）：列表层与每条 entry 的双层 MAC 都必须用同一 `root` 验过，且 `issued_at <= now`、`sequence >= min`，否则一律抛 `ValueError`。审核通过后命中语义与逐次列表相同：命中某条所用证书即永久撤销。`revocations`、`now`、`min` 均仅限关键字传入。

```python
from nearproof import cert, locate_cert

root = b"\x09" * 32
trusts = [cert("alpha", 0.0, 0.0, keys["alpha"], root),
          cert("bravo", 3.0, 0.0, keys["bravo"], root),
          cert("charlie", 0.0, 4.0, keys["charlie"], root)]
consensus = locate_cert(records, (0.0, 0.0), context, trusts, root)
consensus.accepted                     # True
```

### 单证书永久撤销 `TrustRevocation` 与 `revoke_trust`

`TrustRevocation(version, id, target, mac)` 是根密钥 MAC 的冻结**单证书永久**撤销记录，按字段序位置构造、冻结且按字段相等。字段类型依次为 `int`/`str`/`bytes`/`bytes`；构造时即校验全部字段契约——**形状错（字段类型不对）抛 `TypeError`，值违约抛 `ValueError`**：`version` 必须为 `1`；`id` 为非空字符串，且等于被撤销证书的 id；`target` 为恰好 32 字节的 `bytes`，且等于被撤销证书（`VerifierTrust`）的 `mac`，因此一条撤销只能撤销 target 精确对应的那一张证书；`mac` 为恰好 32 字节的 `bytes`。`mac = HMAC-SHA256(root, b"NPVR1" + 去 mac 规范 JSON)`，前缀与编码直接拼接、无分隔符、无长度前缀；记录本身不含根密钥。

`to_bytes()` 按无空白 UTF-8 JSON 编码：键依字段顺序（`version, id, target, mac`），`target`/`mac` 为小写十六进制，无长度前缀。`from_bytes(data)` **仅收 `bytes`**（非 bytes 抛 `TypeError`）：键必须恰好是四个字段、各出现一次且依字段顺序，`target`/`mac` 为解码后恰 32 字节的小写十六进制，`version`/`id`/字段类型违约分别按 `TypeError`/`ValueError` 抛出；解析与字段校验后按规范重编码并与输入逐字节比较，任何格式化 JSON、空白或非规范写法均抛 `ValueError`；它不校验 MAC。

`revoke_trust(trust, root)` **仅接受 `VerifierTrust` 实例**（不接受字节编码；其他任何类型抛 `TypeError`），`root` 必须是非空 `bytes`（非 bytes 抛 `TypeError`，空 bytes 抛 `ValueError`）。返回的记录 `version` 固定为 `1`、`id` 取自该证书、`target` 等于该证书的 `mac`；签发是纯计算，不触碰任何验证者状态。签发的记录（或其字节编码）通过 `locate_cert(..., revocations=...)` 传入后生效，语义见上节。

```python
from nearproof import revoke_trust

revocation = revoke_trust(trusts[0], root)
blob = revocation.to_bytes()           # 可持久化或传输
# locate_cert(records, point, context, trusts, root, revocations=[blob])
```

### 根签名撤销快照 `TrustRevocationList`、`make_crl` 与 `audit_crl`

`TrustRevocationList(version, sequence, issued_at, entries, mac)` 是根密钥 MAC 的冻结**全局撤销快照**，按字段序位置构造、冻结且按字段相等：`version` 必须为 `1`；`sequence` 为非布尔、取值在 u64 范围内的 `int`；`issued_at` 为非布尔、有限、非负的数，**构造时即转为 `float`**；`entries` 必须是 `tuple`，元素全部是 `TrustRevocation`，且按 `(id, target)` 严格升序、无重复对（相等或逆序均抛 `ValueError`，允许空元组）；`mac` 为恰好 32 字节的 `bytes`。任何值违约一律抛 `ValueError`。

`to_bytes()` 为字段序紧凑 UTF-8 JSON：`entries` 编码为**对象数组**，每个对象就是一条完整的 `TrustRevocation` 规范对象（键序 `version, id, target, mac`，含各自的 `mac`），列表自己的 `mac` 为最后一个键的小写十六进制；无空白、无 NaN/Infinity、无长度前缀。`from_bytes(data)` **仅收 `bytes`**（非 bytes 抛 `TypeError`）：外层键必须恰好是五个字段且依字段顺序，`entries` 必须是数组且每个对象满足完整的 `TrustRevocation` 字节契约，字段值违约（u64、有限非负 float、mac 恰 32 字节、排序/去重）以及重编码后与输入非逐字节相等（格式化 JSON、空白、整数写法的 `issued_at` 等）一律抛 `ValueError`；成功返回本类实例，**不校验列表 MAC，也不校验任何 entry MAC**。

`make_crl(items, seq, time, root)` 用 root 对一批 `TrustRevocation` 签快照：`items` 为其可迭代对象（**不接受字节**，元素类型不对抛 `ValueError`），可为空；条目复制后按 `(id, target)` 升序排列，重复对抛 `ValueError`；`seq`/`time` 须满足上述字段契约，`version` 固定为 `1`。`root` 必须是非空 `bytes`（非 bytes 抛 `TypeError`，空 bytes 抛 `ValueError`），且必须与签发各条 entry 所撤销证书的是**同一个 root**。`mac = HMAC-SHA256(root, b"NPVRL1" + 去mac规范JSON)`，前缀与编码直接拼接、无分隔符、无长度前缀；entry 自身的 MAC 原样带入。签发是纯计算。

`audit_crl(x, root, now, min=0) -> None` 收快照对象或其规范字节（其他类型抛 `ValueError`；字节不合契约同样抛 `ValueError`）。`root` 规则同上；`now` 必须是非布尔有限数（否则 `ValueError`），`min` 必须是非布尔 `int`。恒时比较**双层 MAC**：列表层按 `NPVRL1` 重算，且每条 entry 的根 MAC 按 `NPVR1` 用同一 root 逐一重算——任一层不符即抛 `ValueError`。此外 `issued_at > now`（未来快照）或 `sequence < min`（序号过旧）均抛 `ValueError`；成功返回 `None`。

```python
from nearproof import make_crl, audit_crl, revoke_trust

items = [revoke_trust(t, root) for t in revoked_trusts]   # 顺序任意，可空
crl = make_crl(items, seq=42, time=1_700_000_000.0, root=root)
blob = crl.to_bytes()                                     # 可持久化或分发
audit_crl(blob, root, now=1_700_000_600.0, min=42)        # 成功返回 None
# locate_cert(records, point, context, trusts, root,
#             revocations=blob, now=1_700_000_600.0)
```

### 认证共识证据 `CertifiedConsensusEvidence`、`locate_cert_evidence` 与 `audit_cert_evidence`

`CertifiedConsensusEvidence(version, body, mac)` 是根密钥 MAC 的冻结**共识证据**，把一次 `locate_cert` 运行的查询、全部参与项与共识结果封装成可长期保存的自证快照：按字段序位置构造、冻结且按字段相等。`version` 固定为 `1`；`body` 必须是 `bytes`（不接受 `bytearray`/`str`，不做隐式转换）；`mac` 必须是恰好 32 字节的 `bytes`；任何违约在构造时抛 `ValueError`。构造时不解释 `body` 的内容——合规 `body` 由 `locate_cert_evidence` 产生、由 `from_bytes` 校验。

**双层紧凑 JSON**。`to_bytes()` 的外层是单个紧凑 UTF-8 JSON 文档，键序固定为 `version, body, mac`，`body` 与 `mac` 均为小写十六进制字符串，无空白、无 NaN/Infinity、无长度前缀。`body` 解码后必须恰为数组 `[point, context, records, trusts, consensus]`：

- `point` 为恰好两个**有限、非布尔**数的裸 JSON 数组（无类型标签、无长度前缀）；
- `context` 为**非空**字符串；
- `records`/`trusts` 为**小写规范十六进制字符串数组**，每个元素解码后分别是一条合规的 `BoundAttestedObservation.to_bytes()` / `VerifierTrust.to_bytes()` 编码；两数组按 id 序唯一对应——记录按 id 升序、id 唯一，同索引位置的信任 id 必须相同（缺漏、未知、错序均抛 `ValueError`）；
- `consensus` 按 `Consensus` 字段序为数组 `[total, support, rejected, accepted]`，`total`/`support` 为非布尔整数，`rejected` 为按字典序排列、非空且不重复的字符串数组，`accepted` 为布尔值。

内层 `body` 本身也必须是规范紧凑 JSON：`from_bytes` 解析并校验全部字段契约后，对内层重编码并与原 `body` 字节逐字节比较，再对整个外层重编码与输入逐字节比较；任何格式化 JSON、空白、非规范数字/字符串写法一律抛 `ValueError`。`to_bytes()` 同样执行该内层规范重编码比对——构造器对 `body` 不透明，但序列化时若 `body` 不是规范紧凑 JSON（非 JSON、带空白或非规范拼写）则抛 `ValueError`，且实例已冻结、绝不以重编码结果改写 `body`。`from_bytes(data)` 只收 `bytes`（其他类型抛 `ValueError`），**不校验 MAC**——用 `audit_cert_evidence` 配合 root 才验签。

`locate_cert_evidence(records, point, context, trusts, root)` 的参数就是不带撤销选项的 `locate_cert`（可撤销的运行不应被冻结进长期证据）：先按与 `locate_cert` 相同的混输规则物化记录与信任（对象/字节、生成器均可），再原样跑一遍 `locate_cert`，故全部既有契约与异常（`root` 非 bytes 抛 `TypeError`、空 bytes 与其余违约抛 `ValueError`）保持不变。成功后把参与记录按 id 排序、信任按同 id 序对齐，二者取各自规范字节编码的小写十六进制放入 `records`/`trusts`，点、用途与 `Consensus`（`rejected` 转字典序数组）组成 `body`，并计算 `mac = HMAC-SHA256(root, b"NPCCE1" + body)`——前缀与 `body` 直接拼接，无分隔符、无长度前缀；结果与输入顺序无关，函数纯计算。

`audit_cert_evidence(x, root) -> Consensus` 收证据对象或其规范字节（其他类型或不合契约的字节抛 `ValueError`）；`root` 必须是非空 `bytes`（非 bytes 抛 `TypeError`，空 bytes 抛 `ValueError`）。它先用 root **恒时**复核外层 MAC（`HMAC-SHA256(root, b"NPCCE1" + body)`），不符即抛 `ValueError`；MAC 通过后解析 `body`，取出其中的记录、信任、点与用途**重跑一次 `locate_cert`**（每条记录 MAC、每张证书 root MAC 全部重新恒时核验，几何重新聚合），重算的 `Consensus` 必须与 `body` 所载逐字段相等（含字典序 `rejected` 元组），否则抛 `ValueError`——因此即使攻击者持有 root、改写共识或参与项后重新签名，重算不一致仍会被拒。成功返回重算的 `Consensus`。

```python
from nearproof import locate_cert_evidence, audit_cert_evidence

evidence = locate_cert_evidence(records, (0.0, 0.0), context, trusts, root)
blob = evidence.to_bytes()                 # 可持久化或分发
consensus = audit_cert_evidence(blob, root)
consensus.accepted                         # True
```

### CRL 快照证明 `CrlProof`、`prove_crl` 与 `audit_proof`

`CrlProof(version, body, mac)` 是根密钥 MAC 的冻结 **CRL 快照证明**，把一次带签名撤销快照的 `locate_cert` 运行的查询、全部参与项、快照本体、`now`/`min` 与共识结果封装成可长期保存的自证快照：字段契约、冻结/相等/位置构造语义与 `CertifiedConsensusEvidence` 完全相同（`version=1`；`body` 为 `bytes`；`mac` 恰 32 字节 `bytes`；违约抛 `ValueError`）。

**双层紧凑 JSON**。外层与共识证据相同：单个紧凑 UTF-8 JSON 文档，键序固定 `version, body, mac`，`body`/`mac` 为小写十六进制，无空白、无长度前缀。`body` 解码后必须恰为数组 `[point, context, records, trusts, crl, now, min, consensus]`：

- `point` 同共识证据：恰好两个有限、非布尔数的裸 JSON 数组；
- `context` 为非空字符串；
- `records`/`trusts` 同共识证据：参与记录/信任的规范小写 hex 数组，按参与项 id 升序、同索引按 id 一一对应；
- `crl` 为一个小写规范十六进制字符串，解码后是合规的 `TrustRevocationList.to_bytes()` 编码；
- `now` 为有限、非布尔数（生产时以 `float(now)` 写入），`min` 为非布尔整数；
- `consensus` 为 `[total, support, rejected, accepted]`，规则同共识证据。

内层 `body` 的规范重编码逐字节比对、`to_bytes()` 不改写非规范 `body`、`from_bytes()` 只收 `bytes` 且不验 MAC 等规则均与 `CertifiedConsensusEvidence` 一致。

`prove_crl(records, point, context, trusts, root, crl, *, now, min=0)` 按 `locate_cert` 的**签名快照路径**（`revocations=crl`、`now` 必填、`min` 默认 `0`，二者仅限关键字）求共识：`crl` 收 `TrustRevocationList` 对象或其规范字节；快照先经 `audit_crl` 整体审核（双层 MAC、`issued_at <= now`、`sequence >= min`），命中项永久撤销参与证书，无关条目不影响共识。记录与信任按与 `locate_cert` 相同的混输规则物化后再运行，故结果与输入顺序无关、函数纯计算。成功后参与记录按 id 升序、信任按同 id 序对齐，连同 `crl` 取各自规范字节编码的小写十六进制，与点、用途、`now`（float）、`min`、`Consensus`（`rejected` 转字典序数组）组成 `body`，并计算 `mac = HMAC-SHA256(root, b"NPCCE2" + body)`——前缀与 `body` 直接拼接，无定界符、无长度前缀。`root` 的契约与 `locate_cert` 相同：非 bytes 抛 `TypeError`，空 bytes 及其他违约抛 `ValueError`。

`audit_proof(x, root) -> Consensus` 收证明对象或其规范字节（其他类型或不合契约的字节抛 `ValueError`）；`root` 必须是非空 `bytes`——类型错误抛 `TypeError`，空值抛 `ValueError`。它先用 root 恒时复核外层 MAC（`HMAC-SHA256(root, b"NPCCE2" + body)`），再按 `body` **重放快照路径**：先对所载 `crl`、`now`、`min` 跑一遍 `audit_crl`（列表层 `NPVRL1` 与每条 entry 的 `NPVR1` 双层 MAC、未来时间与序号下限全检），再以该快照对所载记录、信任、点、用途重跑 `locate_cert`；重算的 `Consensus` 必须与 `body` 所载逐字段相等，否则抛 `ValueError`。除 `root` 类型外的一切失败（包括重放过程中冒出的 `TypeError`）一律报为 `ValueError`。成功返回重算的 `Consensus`。

```python
from nearproof import make_crl, prove_crl, audit_proof

crl = make_crl(revocations, 3, 100.0, root)
proof = prove_crl(records, (0.0, 0.0), context, trusts, root, crl,
                  now=100.0, min=3)
blob = proof.to_bytes()                  # 可持久化或分发
consensus = audit_proof(blob, root)
consensus.accepted                       # True
```

### 防回滚前沿 `CrlState` 与 `CrlProofAuditor`

无状态的 `audit_proof` 只认证单个证明，攻击者仍可把一张序号更低（更旧）的快照证明重新送达。`CrlState` 与 `CrlProofAuditor` 在其之上加一道单调门控，防止 CRL 序号回退。

`CrlState(version, sequence, digest, mac)` 是冻结的根密钥 MAC **检查点记录**：位置构造、按字段相等，字段契约、编码规则与其余记录一致——`version=1`；`sequence` 为非布尔 u64（最近通过审计的 `TrustRevocationList.sequence`）；`digest` 恰 32 字节，即证明 body 所载**规范 CRL 字节**（`TrustRevocationList.to_bytes()`，在证明里以小写 hex 承载）的 `SHA256`；`mac` 恰 32 字节，`mac = HMAC-SHA256(root, b"NPCK1" + 去mac规范编码)`，前缀与编码直接拼接、无定界符、无长度前缀。任何字段违约在构造时抛 `ValueError`，记录本身不含 root。

`to_bytes()` 输出字段序紧凑 UTF-8 JSON（键序 `version, sequence, digest, mac`，`digest`/`mac` 为小写 hex，无空白、无长度前缀）。`from_bytes(data)` **仅收 `bytes`**（其他类型抛 `ValueError`）：键必须恰好四个、各一次且依字段序（缺失、多余、重复、乱序即拒），`version == 1`，`sequence` 为非布尔 u64，两个 hex 字段须解码为恰好 32 字节；解析后重编码须与输入逐字节相等；**不验 MAC**。

`CrlProofAuditor(root, *, checkpoint=None)` 持有当前前沿：

- `root` 必须是非空 `bytes`——非 bytes（含 `bytearray`/`str`/`None`）抛 `TypeError`，空值抛 `ValueError`。
- `checkpoint` 仅限关键字。`None`（默认）为空状态；否则收 `CrlState` 对象或其规范字节，字节先过 `CrlState.from_bytes` 契约，再以 `root` 恒时复核其 `NPCK1` MAC——编码不合契约或 MAC 不符抛 `ValueError`。审计器自身不做任何持久化：**重启时调用方必须把上次保存的最新检查点传回来**（取 `checkpoint` 属性、`to_bytes()` 落盘）。
- `audit(proof) -> Consensus` 收 `CrlProof` 或其规范字节。先调用无状态 `audit_proof`（全部密码学、规范性与重放检查照原样执行）；成功后才取证明所载 CRL 的序号与规范字节哈希，在锁内与当前前沿比较并更新：
  - **低序拒绝**：`sequence` 低于前沿抛 `ValueError`；
  - **同序仅同哈希重放**：序号相等且 `digest` 相同则视为重放，返回共识但不改动检查点；序号相等而 `digest` 不同（同序号的另一张快照）抛 `ValueError`；
  - **高序推进**：序号更高则生成并 MAC 新的 `CrlState`。
- 比较与更新在同一把锁内原子完成：任何失败（含 `audit_proof` 失败、低序、同序异哈希）都不改动检查点，并发审计绝不可能把前沿回退。
- 只读属性 `checkpoint: CrlState | None` 导出当前前沿（首次成功审计前为 `None`）；返回的是冻结对象，外部无法借此改写内部状态。

除 `root` 类型错误抛 `TypeError` 外，其余失败一律抛 `ValueError`；旧接口（`audit_proof` 等）行为不变。

```python
from nearproof import CrlProofAuditor

auditor = CrlProofAuditor(root)
auditor.audit(proof1)                     # sequence=1，首次推进
saved = auditor.checkpoint.to_bytes()    # 调用方自行持久化

# ... 重启后：
auditor = CrlProofAuditor(root, checkpoint=saved)
auditor.audit(proof1)                     # 同序同哈希：重放，接受
auditor.audit(proof_old)                  # 低序：ValueError，前沿不变
auditor.audit(proof2)                     # sequence=2：推进
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
