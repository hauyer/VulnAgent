# WP7 — UI / 展示

## 目标（开发指导书 WP7）

复用现有核心 API 提供展示型 UI：任务全链可追溯（Trace）、候选与证据、
独立复核、失败/未运行状态、实验与案例页；前端构建与 API 契约通过，
并交付三条现场固定演示路线。页面只展示事实，不另建安全判定逻辑。

## 交付

### 前端（`frontend/`，Vite + React + TypeScript + Tailwind v4）

- **Dashboard**：新建任务（目标路径 + 类型，创建即运行）、任务列表、
  状态徽章（等待/分析中/运行中/已完成/失败，文案颜色区分）。
- **TaskDetail**：五个页签
  - Trace：事件时间线（producer + payload 全文）
  - 候选：CWE/来源/置信度/位置 + **人工复核按钮**（PUT review）
  - 证据：类型/来源/artifact/结构化 data
  - 复核：CONFIRMED/REJECTED/UNCERTAIN 徽章
  - 报告：HTML/PDF 下载
- **Experiments**：只读研究 API 展示实验产物（metrics/summary/候选计数）。
- 构建输出 `dist/`（仓库根），由 FastAPI `_mount_built_frontend` 挂载；
  开发模式 Vite 代理 `/api` → `:8000`。
- 门禁命令：`npm run lint`（tsc --noEmit）、`npm run build` 均通过。

### 只读研究 API（`src/vulnagent/api/experiments.py`）

- `GET /api/experiments`：实验列表（`artifacts/experiments/` 下合法目录）。
- `GET /api/experiments/{experiment_id}`：summary.json / metrics.json /
  candidates.jsonl 计数；id 白名单 `[a-z0-9_-]`，路径穿越一律 404。

### 演示文档（`docs/06_presentation/demo_routes.md`）

三条现场路线（12–15 分钟）：
1. 主链闭环（准入→事实→候选→复核→报告，含人工标注）；
2. 真实动态缺陷（WP4 crash/sanitizer/replay/fixed_outcome + 缺工具诚实状态）；
3. 研究探索（WP5 盲评 TP/FP/Precision、泄漏守卫；WP6 卷宗"未提交"与
   被排除误报 + 最有价值候选）。

## 契约与测试

- `tests/unit/test_wp7_api_contract.py`：OpenAPI 必须暴露 UI 用到的
  10+ 路径；实验 API 穿越尝试全 404；dist 存在时前端挂载不遮蔽 /api。
- 既有 `tests/integration/test_frontend_delivery.py` 继续通过（6 项）。

## 复现

```bash
cd frontend && npm install && npm run lint && npm run build
.\.venv\Scripts\python.exe -m uvicorn vulnagent.api.app:app --port 8000
# 浏览器打开 http://127.0.0.1:8000/ （dist 已挂载）
```

## 边界

- 页面不实现任何漏洞判定逻辑，只展示后端事实与状态；
- "未运行/未确认/确认"三态文案颜色固定，工具缺失显示 unavailable/not_run。
