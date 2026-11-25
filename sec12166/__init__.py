"""离线安全复核 12166 —— 仅使用 Python 3.12 标准库。

模块划分：
- model      : 合成路径节点 / ACE / 策略版本、规范序列化、摘要、带计量仓储
- authz      : Windows 风格继承(OI/CI/NP/IO)、子树拒绝、断开继承、挂接点解析
- synthetic  : 确定性合成“路径 / 策略 / 授权代规则”，并限定只能读合成根
- countersign: 会签绑定(旧版/新版/租户/隔离目录摘要) + 两名实际控制人独立
- durable    : WAL + 原子快照、幂等键、回执丢失注入与重开恢复
- concurrency: 双线程 Barrier 并行回退/撤回与屏障复测
- difftree   : 小树恢复前后差异区间 + 最短可复核放行/拒绝见证路径
- scalecheck : 60000 节点实际访问计数、未改分区哈希、全量结果
"""

__version__ = "1.0.0"
SEED = 20261126
TOTAL_SCALE_NODES = 60_000
