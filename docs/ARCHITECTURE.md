# 架构

## 一句话

`text → parse(AST) → rules(findings) → score → policy → decision`，
全程只读字符串，没有一步会执行输入。

```
                 ┌──────────────┐
  command text → │  shell.py    │ → Script(pipelines → segments → argv/redirects/subs)
                 └──────────────┘
                        │
        ┌───────────────┼────────────────┐
        ▼               ▼                ▼
   segment rules   cross-segment    policy.observed_capabilities()
   (BR0xx, 逐段)   (BR0xx, 跨管道)   (从 AST 直接推导能力，供策略匹配)
        └───────────────┴────────────────┘
                        ▼
                  findings[]  (rule_id, capability, severity, evidence, why, instead)
                        ▼
                   score.py  → 0..100
                        ▼
                  policy.py → allow | ask | deny (+ 命中的规则理由)
                        ▼
                  report.py → 人读 / JSON / hook 载荷 / SARIF-ish
```

## 组件职责

| 文件 | 职责 | 关键不变量 |
|---|---|---|
| `shell.py` | POSIX-ish 词法与结构解析；包装器解包；载荷提取（`-c`、ssh、docker exec、heredoc） | 输入 ≤100 KiB、段 ≤4096、递归 ≤4 层；任何异常都 best-effort 并写 `notes`，不抛给调用方 |
| `rules.py` | 45 条规则；能力词表；`classify_target()` 路径分级；`observed_capabilities()` | 纯函数，无 IO；单条规则抛异常不影响其他规则 |
| `score.py` | 严重度权重 → 衰减聚合 → 阈值判定 | 确定性，同输入同输出 |
| `policy.py` | JSON 策略加载/校验/求值；三个预设 | deny 优先于 allow；未知键拒绝加载 |
| `report.py` | 人读报告、稳定 JSON、hook JSON | JSON 字段有测试锁 |
| `cli.py` | 子命令、退出码、stdin/文件输入、错误处理 | 0/2/3/4 四码契约；`guard` 永远 exit 0 |
| `corpus.py` | 169 条语料（危险 + 安全孪生对） | `br selftest` 是唯一的真相来源 |

## 解析器为什么要自己写

`shlex` 会把 `2>&1` 变成 token `2>&1`、把 heredoc 正文当普通词、丢掉 `$()` 的内部结构，
而这些恰好是判断影响面最需要的信息。所以 `shell.py` 自己做一个**结构化**但不求完整的解析器：

```
Script   = [Pipeline]
Pipeline = [Segment] (+ 段间连接符 | && || ; & 换行)
Segment  = argv[] + redirects[] + text + subs[]
Redirect = fd + op + target + body(heredoc) + sub(进程替换)
```

它明确不做：变量展开、通配展开、别名、算术展开、完整 `case/for` 语法。
不做这些不是偷懒，是因为**静态分析不应该假装知道运行时的值**——不知道就标"未知"，让策略去 ask。

### 包装器解包

`sudo env A=1 timeout 5 rm -rf /` 的真实程序是 `rm`。`unwrap()` 迭代剥掉：

- 前置赋值 `VAR=value`（`FOO=1 rm` 是 `rm`）
- `sudo/doas/env/command/nohup/nice/time/stdbuf/timeout/setsid/chroot/unbuffer/xargs`
- 各包装器自己的取值 flag（`-u root`、`-n 19`、`-s KILL`）与位置参数（`chroot NEWROOT`、`timeout DURATION`）

之所以按"表 + 位置参数"而不是正则，是因为 `sudo -u root rm` 和 `sudo rm -u root` 必须区分开。

### 载荷递归

以下位置的字符串会被当成**子脚本**再解析一遍（深度上限 4）：

- `sh -c '…'`、`python -c '…'`、`perl -e '…'`、`node -e '…'`
- 代码里的 `os.system("…")` / `subprocess.run("…")` / `system("…")`（正则提取引号内文本）
- `ssh host '…'`、`kubectl exec pod -- …`、`docker exec c …`
- `$(…)`、反引号（引号感知：双引号里的单引号不改变上下文）
- 重定向目标 `> "$(…)"`、进程替换 `<(…)`
- `bash <<EOF … EOF` 的正文，以及 `eval`

少了任何一条，`bash -c "$(curl …)"` 这一类就会整体漏掉。

## 能力模型

能力是**封闭词表**（23 类），规则只能产出这些标签。策略因此可以稳定地按能力写，
而不用记住 45 个规则号：

```
fs.write  fs.delete  fs.device_write  fs.chmod  fs.chown  fs.move
cred.access  cred.protect  cred.export
net.egress  net.ingress  net.remote_exec  net.exfil  net.upload  net.serve
priv.escalate  sys.persist  sys.service  sys.kernel  sys.reboot
deploy.prod  git.destructive  pkg.install  db.destructive  container.destructive
opaque.code
```

`observed_capabilities(text)` 从 AST 直接推导"这条命令会触碰什么"，**不依赖是否触发规则**。
这样 `deny fs.delete` 能拦住 `rm -rf node_modules`（它不产生 finding，但确实是 delete），
策略作者不必和规则的严重度阈值斗智。

## 评分

```
weight = {info: 2, low: 6, medium: 16, high: 38, critical: 65}
score  = Σ weight_i · 0.55^i        (i 按权重降序，取前 12 条)
       + 6                          (若不同能力种类 ≥ 3)
score  = min(score, 100)
```

衰减的原因：5 条 low 不等于 1 条 critical，但也不能因为凑数把分数堆到 deny。
6 分能力多样性加成：`rm -rf` + `git push --force` + `curl -d @` 同时出现，比单一看更值得警惕。

阈值：`score ≥ 65` deny、`≥ 15` ask。选 15 而不是 22，是因为 **medium(16) 必须 ask**——
"悄悄放行一个 medium"是最难被发现的失败。

## 策略求值

```
if any(deny rule matches):  deny
elif any(ask rule matches): ask
elif any(allow rule matches): allow
else: score 阈值判定
```

规则内多条件 AND，规则间 deny 优先。仓库里的 `.br-policy.json` 因此**不能**把设备写入解封——
它只能加严，除非显式只写 allow 且没有 deny/ask 命中。

## 失败模式

| 情况 | 行为 | 理由 |
|---|---|---|
| 解析不完全（截断、段超限） | 附加 `BR099`（medium 或 high），并额外解析末尾 4 KiB | "看不懂"不能等于"安全" |
| 规则函数抛异常 | 吞掉该条 finding，其余继续 | 一条规则写错不该让整条命令失去保护 |
| 策略文件非法 | exit 4 + 具体行号式提示 | 静默忽略一条 deny 是灾难 |
| hook payload 非法 | 输出 ask 的合法 JSON，exit 0 | 不把宿主 agent 弄崩 |
| 命令为空/非字符串 | allow，不介入 | 不是我们管的范围 |

## 测试策略

- `test_shell`：与真实 shell 行为对照（引号、`&&`、heredoc、`2>&1`、`$()`）
- `test_rules`：危险/安全孪生对，锁住"不该报"的精度
- `test_policy`：预设、覆盖、非法配置、deny 优先
- `test_cli`：退出码契约、JSON 结构、hook 载荷、错误路径
- `test_safety`：AST 级"包内无执行原语"、金丝雀文件、400 条模糊输入、性能上界、确定性
- `corpus.py`：169 条端到端期望（`br selftest`）
