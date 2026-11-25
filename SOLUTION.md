# SOLUTION — 离线复现与复核 12166

仅用 **Python 3.12 标准库**，对“隔离策略回退后，本该封闭的分区出现允许项”做
**离线、合成数据**的复现与复核。不读取真实 Windows 路径 / ACL / 注册表 / 线上策略；
所有“路径、策略、授权代规则”都是确定性合成物，且读取侧被 `SyntheticJail` 限制在
`synthetic/` 目录内（绝对盘符、UNC、`..`/`..\` 穿越一律拒绝）。

## 0. 一键运行

```bash
python solve.py
```

或 Windows 下 `run.cmd`。退出码 `0` = 全部机器断言通过，`1` = 有失败项。

```bash
python -m unittest discover -s tests -v
```

运行后生成：

| 路径 | 内容 |
|---|---|
| `synthetic/authz_rules.json` | 主体/组、判定优先级、继承标志、双人独立控制规则 |
| `synthetic/policies.json` | 旧版 v2 / 新版 v3 策略、租户、规模常量 |
| `synthetic/small_tree.json` | 独立小树两版 DACL（19+5 节点） |
| `synthetic/scale_paths.jsonl` / `scale_meta.json` | 恰好 60000 节点规模树 |
| `reports/report.json` / `reports/REPORT.md` | 全量结构化结果与人工复核报告 |
| `reports/full_access_results.csv` | **60000 行**全量访问判定 |
| `artifacts/concurrency/` | WAL、幂等键、回执恢复的真实落盘状态（gitignore） |

> `synthetic/` 由固定结构确定性生成（无随机数），可删除后由 `solve.py` 重建并复算。

## 1. 题面要求 → 实现 → 可核验点

| 题面要求 | 实现位置 | 关键可核验结果 |
|---|---|---|
| 仅读合成路径/策略/授权代规则 | `synthetic.SyntheticJail` | 5 项监牢自检：正常读 2 项 + 盘符/正斜杠穿越/反斜杠穿越 3 项必拒 |
| 会签绑定旧版、新版、租户、隔离目录摘要 | `countersign.binding_core/approve/verify_ticket` | HMAC-SHA256 绑定 `old_version/new_version/tenant/isolation_digest`（另含两版策略摘要）；改任一字段验签失败 |
| 两名实际控制人独立 | `countersign.verify_ticket` + `authz_rules.dual_control` | 校验不同 `cid/person_id/control_group/派生密钥`，且不得是提交人；6 个负例全拒（改租户/改摘要/同人两次/共享密钥/票-现场摘要不符/提交人兼任） |
| 继承允许 | `authz.propagate_to_child/effective_aces` | OI/CI/NP/IO 完整传播；见证中 allow 为 `inherited`、`origin=100` |
| 子树拒绝（拒绝优先） | 同上 + `evaluate_access` | HR `105–108` 对 `bob` 为 DENY，且同时存在可竞争的继承 ALLOW |
| 挂接点 | `authz.resolve_through_mount/evaluate_mounted_path` | 挂接点 `111` 自身新版 DENY；穿过 `111→201→readme.txt(202)` 按目标 DACL 判 ALLOW；枚举/回退不跨入目标 |
| 断开继承 | `Node.block_inheritance`（SP_DACL_PROTECTED 语义） | Vault `109/110` 新版丢弃祖先 ACE → IMPLICIT_DENY；旧版未断开 → ALLOW |
| 两线程并行回退/撤回 | `concurrency`（`threading.Barrier(2)`） | 场景 A/B + 32 轮无编排竞态，XOR 终态不变量 0 违例 |
| 屏障复测：撤销先持久化 | `scenario_revoke_first` | 撤回 WAL 先 fsync → 回退抛 `RevocationFence`，副作用 0、版本仍为新版 |
| 屏障复测：承诺成功但回执丢失 | `scenario_receipt_lost` + `durable` | 提交事件 fsync 后注入 `ReceiptLost`；同键重试与“重开进程重放 WAL”均返回同一 receipt，`effects.log` 恰 1 条 |
| 小树差异区间 + 最短可复核路径 | `difftree.build_diff_report` | DFS 序 `101…111`，差异区间 **[0..3] 与 [8..10]，长度 [4,3]**，11 节点中 7 个结论变化；输出最短 ALLOW / ALLOW 文件 / DENY / 挂接 ALLOW / 断开继承 5 类见证链 |
| 6 万节点核验实际访问数 | `scalecheck.run_scale_check` + `Repo.meter` | **实际读取唯一节点 44905、规则适用/变更 44904**，与独立 `rule_scope_ids` 集合、算术常量三重对账 |
| 未改分区哈希 | `model.partition_digest` | 回退前后 P-B/P-C/P-D 摘要逐字符相同，P-A 必变 |
| 全量结果 | `reports/full_access_results.csv` | 60000 行，分类计数对账到 60000；ALLOW 47405 / DENY 3000 / IMPLICIT_DENY 9595 |

## 2. 规模树算术（数字是“算”出来并被断言锁死的，不是观测巧合）

每支完整主干 = `1 主干 + 40 叶子目录 + 40×50 文件 = 2041` 节点。

```
P-A = 根1 + Isolation1 + (22 正常支 + 1 断开继承支)×2041 + 挂接点1 + Other(1+499)
    = 47446
P-B = 1 + 2999 = 3000
P-C = (1 + MountedData1 + 99) + 1899 = 2000
P-D = 1 + 7553 = 7554
合计 = 47446 + 3000 + 2000 + 7554 = 60000
```

回退作用域（从 `Isolation=2` 传播可继承规则）：

```
访问 = Isolation 1 + 22×2041 正常支 + 断开边界节点 box-block 1 + 挂接点 1 = 44905
适用/变更 = 访问 − 1（box-block 读到即裁剪、不适用）                 = 44904
被断开继承整支裁剪、完全不读的后代 = 2041 − 1 = 2040
```

挂接目标 `P-C\MountedData` 绝不进入读取集；读取集 100% 落在 P-A / 目标租户内。
朴素全树扫描会访问 60000；本方案只访问 44905，且差异可逐节点集合复核。

## 3. “回退后出现允许项”的复现结论

旧版 v2 相对新版 v3：① 缺少 `Sealed` 上的子树拒绝；② Vault 未断开继承；
③ Isolation 规则只拒 `WRITE` 不拒 `READ`。于是祖先 `Users:READ(OI|CI)` 一路放行。
恢复新版后，DFS 区间 `[0..3]`（Sealed/Dropbox 段）与 `[8..10]`（Vault/secret/Bridge）
重新封闭；HR 段因两版都有子树拒绝而保持 DENY（差异表中的“不变岛”，防止只看继承允许）。
**唯一在策略恢复后仍残留的放行面是挂接别名** `Sealed\Bridge\readme.txt → P-OPEN\...`：
封闭区 DACL 管不到 reparse 目标自身的 DACL，必须删除挂接点或在目标侧同样封闭。
这正是“还要考虑挂接点”的复核价值。

## 4. 设计说明

- **拒绝优先 + 规范顺序近似**：显式 deny/allow 先于继承 deny/allow；单权限位匹配。
- **持久化**：append-only WAL（逐条 `flush+fsync`，SHA256 校验，按精确 `\n` 分帧，
  末尾撕裂记录在重放时截断）为唯一事实源；检查与线性化写都在同一把 `RLock` 内，
  因此回退/撤回不可能同时生效。幂等键保证丢回执安全重试。
- **不夸大语义**：HMAC 是离线合成的会签令牌；真实环境应换智能卡/非对称签名，
  但“绑定四要素 + 两名实际控制人独立”的复核口径一致。
- 代码包 `sec12166/` 与 `tests/` 全部仅 import 标准库。
