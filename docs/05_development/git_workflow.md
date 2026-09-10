# VulnAgent Git Workflow

## 1. 长期分支

仓库保留：

- main
- develop

main：

稳定版本。

develop：

日常集成版本。

## 2. Feature Branch

开发者从 develop 创建自己的 Feature Branch。

格式：

`feature/<module-name>`

例如：

- feature/core-pipeline
- feature/agent-framework
- feature/source-analysis
- feature/binary-analysis
- feature/fuzz-engine
- feature/verification
- feature/llm-knowledge
- feature/platform
- feature/experiments

## 3. 标准开发流程

```text
Issue / Task
    ↓
checkout develop
    ↓
pull
    ↓
create feature branch
    ↓
coding
    ↓
pytest
    ↓
commit
    ↓
push
    ↓
Pull Request
    ↓
Review
    ↓
CI
    ↓
merge develop
```

## 4. Commit Convention

格式：

```text
<type>(<scope>): <description>
```

type：

- feat
- fix
- docs
- test
- refactor
- perf
- chore
- ci

示例：

```text
feat(agent): add base agent interface
feat(core): implement task state machine
fix(api): handle invalid task id
docs(protocol): update evidence schema
test(core): add pipeline tests
```

禁止：

```text
update
111
修改
final
final2
test
修bug
```

## 5. Pull Request

PR 必须说明：

- 修改内容
- 修改原因
- 是否修改公共接口
- 测试结果
- 文档影响

## 6. 公共接口保护

以下修改必须额外 Review：

- Task Schema
- AgentMessage
- Evidence
- VulnerabilityCandidate
- BaseAgent
- BaseLLM
- Public API

不得因个人模块方便擅自修改。

## 7. Merge

Feature：

→ develop

阶段性稳定：

develop → main

禁止：

Feature → main

## 8. 冲突处理

遇到公共 Schema 冲突时：

不要直接通过大量删除代码解决。

应由：

**P1 + 涉及模块 Owner**

统一决定。

## 9. Secret

禁止提交：

- .env
- API Key
- Token
- Password
- Private Key
- Credentials

必须进入：

`.gitignore`

## 10. Large Files

禁止默认提交：

- 大模型文件
- 大规模 Fuzz Corpus
- Core Dump
- 大型 Binary
- 巨量日志
- 数据库文件

必要测试样本应：

**最小化 + 明确来源 + 独立存放。**
