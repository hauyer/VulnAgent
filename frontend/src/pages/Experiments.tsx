import { useEffect, useState } from "react";
import { getExperiment, listExperiments } from "../api";

const EXPERIMENT_LABELS: Record<string, string> = {
  "wp2-multi-engine": "WP2 多引擎静态扫描",
  "wp4-libfuzzer": "WP4 真实 libFuzzer/ASan 动态闭环",
  "wp5-blind-eval": "WP5 盲评基准",
  "wp6-exploration": "WP6 未知目标探索",
  "wp8-ablation": "WP8 引擎组合消融与误报分析",
  "wp8-exploitgym": "WP8 真实 ExploitGym 基准接入（登记/筛选/机理候选）",
  "wp8-unknown-demo": "WP8 未公开目标未知探索示范",
  "wp8-zero-day": "WP8 0day 能力演练（真实 fuzz 未知目标发现）",
};

export default function Experiments() {
  const [list, setList] = useState<string[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadList = () => {
    listExperiments()
      .then((r) => setList(r.experiments))
      .catch((e: unknown) => setError(String(e)));
  };
  useEffect(loadList, []);

  const open = (id: string) => {
    setSelected(id);
    setDetail(null);
    getExperiment(id)
      .then((d) => setDetail(d as unknown as Record<string, unknown>))
      .catch((e: unknown) => setError(String(e)));
  };

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-200 bg-white p-4">
        <h2 className="mb-3 text-base font-semibold text-slate-800">实验与案例</h2>
        {error && <p className="mb-2 text-sm text-red-600">{error}</p>}
        {list.length === 0 ? (
          <p className="py-4 text-sm text-slate-400">
            暂无实验产物。运行实验脚本后，产物会出现在
            <code className="mx-1 rounded bg-slate-100 px-1 font-mono text-xs">artifacts/experiments/</code>
            并通过只读研究 API 展示。
          </p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {list.map((id) => (
              <button
                key={id}
                className={`rounded-md border px-3 py-1.5 text-sm ${
                  selected === id
                    ? "border-slate-800 bg-slate-800 text-white"
                    : "border-slate-300 text-slate-600 hover:bg-slate-50"
                }`}
                onClick={() => open(id)}
              >
                {EXPERIMENT_LABELS[id] ?? id}
              </button>
            ))}
          </div>
        )}
      </section>

      {detail && <ExperimentDetail detail={detail} />}
    </div>
  );
}

function ExperimentDetail({ detail }: { detail: Record<string, unknown> }) {
  const metrics = (detail.metrics ?? detail.summary) as Record<string, unknown> | undefined;
  return (
    <section className="rounded-xl border border-slate-200 bg-white p-4">
      <h3 className="mb-3 font-mono text-sm font-semibold text-slate-800">
        {String(detail.experiment_id)}
      </h3>
      {typeof detail.candidate_count === "number" && (
        <p className="mb-2 text-sm text-slate-600">
          候选行数：<span className="font-semibold">{detail.candidate_count}</span>
        </p>
      )}
      {metrics ? (
        <KeyValueTable data={metrics} />
      ) : (
        <p className="text-sm text-slate-400">该实验无 summary/metrics 数据</p>
      )}
    </section>
  );
}

function KeyValueTable({ data }: { data: Record<string, unknown> }) {
  const rows = Object.entries(data).filter(([, value]) => value !== null && value !== undefined);
  return (
    <table className="w-full text-sm">
      <tbody>
        {rows.map(([key, value]) => (
          <tr key={key} className="border-b border-slate-100">
            <td className="w-56 py-1.5 pr-3 font-mono text-xs text-slate-500">{key}</td>
            <td className="py-1.5">
              {typeof value === "object" ? (
                <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all font-mono text-xs text-slate-700">
                  {JSON.stringify(value, null, 2)}
                </pre>
              ) : (
                <span className="text-slate-800">{String(value)}</span>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
