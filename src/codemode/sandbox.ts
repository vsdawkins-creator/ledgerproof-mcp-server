/**
 * Code Mode sandbox (AGNOSTIC-PLAN.md Phase 4).
 *
 * Generated code runs inside a QuickJS WebAssembly isolate: no network, no
 * filesystem, no process, no environment — `node:vm` is NOT used because it is
 * not a security boundary. The only way out is the `lp` host functions, which
 * the host implements and budgets. API keys stay in the host; the code never
 * sees them.
 */
import {
  getQuickJS,
  shouldInterruptAfterDeadline,
  type QuickJSContext,
  type QuickJSHandle,
} from "quickjs-emscripten";

const SHA256_HEX = /^[0-9a-f]{64}$/i;

export interface PlannedIssue {
  precomputed_sha256: string;
  aiSystemId: string;
  deployerName: string;
  contentCategory: string;
}

/** What the host must provide. All functions may hit the network; the sandbox never does. */
export interface CodeModeHost {
  hash(text: string): Promise<string>;
  verify(sequence: number): Promise<unknown>;
  verifyStatement(statement: string): Promise<unknown>;
  anchor(sequence: number): Promise<unknown>;
}

export interface CodeModeLimits {
  /** Wall-clock budget for the whole run. */
  timeoutMs: number;
  /** QuickJS heap limit. */
  memoryBytes: number;
  /** Max host calls (lp.*) per run. */
  maxHostCalls: number;
  /** Max receipts one run may plan. */
  maxPlannedIssues: number;
  /** Max characters of the returned JSON. */
  maxResultChars: number;
}

export const DEFAULT_LIMITS: CodeModeLimits = {
  timeoutMs: 30_000,
  memoryBytes: 64 * 1024 * 1024,
  maxHostCalls: 20_000,
  maxPlannedIssues: 100,
  maxResultChars: 20_000,
};

export interface RunResult {
  ok: boolean;
  result?: unknown;
  truncated?: boolean;
  error?: string;
  hostCalls: number;
  planned: PlannedIssue[];
}

const PRELUDE = `
const __call = (name, arg) => __host(name, JSON.stringify(arg === undefined ? null : arg)).then((s) => JSON.parse(s));
const lp = Object.freeze({
  hash: (text) => __call("hash", text),
  verify: (sequence) => __call("verify", sequence),
  verifyStatement: (statement) => __call("verifyStatement", statement),
  anchor: (sequence) => __call("anchor", sequence),
  issue: (record) => __call("issue", record),
});
`;

export async function runCodeMode(
  code: string,
  input: unknown,
  host: CodeModeHost,
  limits: CodeModeLimits = DEFAULT_LIMITS
): Promise<RunResult> {
  const QuickJS = await getQuickJS();
  const runtime = QuickJS.newRuntime();
  runtime.setMemoryLimit(limits.memoryBytes);
  runtime.setMaxStackSize(1024 * 1024);
  const deadline = Date.now() + limits.timeoutMs;
  runtime.setInterruptHandler(shouldInterruptAfterDeadline(deadline));
  const vm: QuickJSContext = runtime.newContext();

  let hostCalls = 0;
  const planned: PlannedIssue[] = [];
  const seen = new Set<string>();
  let outstanding = 0;

  const dispatch = async (name: string, arg: unknown): Promise<unknown> => {
    switch (name) {
      case "hash":
        if (typeof arg !== "string") throw new Error("lp.hash expects a string");
        return host.hash(arg);
      case "verify":
      case "anchor":
        if (typeof arg !== "number" || !Number.isInteger(arg) || arg < 0) {
          throw new Error(`lp.${name} expects a non-negative integer sequence`);
        }
        return name === "verify" ? host.verify(arg) : host.anchor(arg);
      case "verifyStatement":
        if (typeof arg !== "string") throw new Error("lp.verifyStatement expects a string");
        return host.verifyStatement(arg);
      case "issue": {
        const r = (arg ?? {}) as Record<string, unknown>;
        const sha = r["precomputed_sha256"];
        if (typeof sha !== "string" || !SHA256_HEX.test(sha)) {
          return { planned: false, reason: "precomputed_sha256 (64 hex chars) is required; raw content is never accepted" };
        }
        for (const f of ["aiSystemId", "deployerName", "contentCategory"]) {
          if (typeof r[f] !== "string" || (r[f] as string).length === 0) {
            return { planned: false, reason: `${f} is required` };
          }
        }
        const key = sha.toLowerCase();
        if (seen.has(key)) return { planned: false, reason: "duplicate hash ignored" };
        if (planned.length >= limits.maxPlannedIssues) {
          return { planned: false, reason: `budget reached (${limits.maxPlannedIssues} per run)` };
        }
        seen.add(key);
        planned.push({
          precomputed_sha256: key,
          aiSystemId: r["aiSystemId"] as string,
          deployerName: r["deployerName"] as string,
          contentCategory: r["contentCategory"] as string,
        });
        return { planned: true, position: planned.length };
      }
      default:
        throw new Error(`unknown host function ${name}`);
    }
  };

  const hostFn = vm.newFunction("__host", (nameH: QuickJSHandle, argH: QuickJSHandle) => {
    const name = vm.getString(nameH);
    const argJson = vm.getString(argH);
    const deferred = vm.newPromise();
    hostCalls += 1;
    if (hostCalls > limits.maxHostCalls) {
      const e = vm.newError(`host-call budget exceeded (${limits.maxHostCalls})`);
      deferred.reject(e);
      e.dispose();
      return deferred.handle;
    }
    outstanding += 1;
    let arg: unknown = null;
    try {
      arg = JSON.parse(argJson);
    } catch {
      arg = null;
    }
    dispatch(name, arg)
      .then(
        (value) => {
          if (!vm.alive) return;
          const h = vm.newString(JSON.stringify(value ?? null));
          deferred.resolve(h);
          h.dispose();
        },
        (err: unknown) => {
          if (!vm.alive) return;
          const h = vm.newError(err instanceof Error ? err.message : String(err));
          deferred.reject(h);
          h.dispose();
        }
      )
      .finally(() => {
        outstanding -= 1;
        if (vm.alive) runtime.executePendingJobs();
      });
    return deferred.handle;
  });
  vm.setProp(vm.global, "__host", hostFn);
  hostFn.dispose();

  const inputH = vm.newString(JSON.stringify(input ?? null));
  vm.setProp(vm.global, "__input", inputH);
  inputH.dispose();

  const source = `${PRELUDE}\nconst input = JSON.parse(__input);\n(async () => {\n${code}\n})().then((v) => JSON.stringify(v === undefined ? null : v))`;

  try {
    const evaluated = vm.evalCode(source, "codemode.js");
    if (evaluated.error) {
      const err = vm.dump(evaluated.error);
      evaluated.error.dispose();
      return { ok: false, error: describe(err), hostCalls, planned: [] };
    }
    const promiseH = evaluated.value;
    const settled = vm.resolvePromise(promiseH);
    promiseH.dispose();
    runtime.executePendingJobs();

    const timeout = new Promise<"timeout">((resolve) => {
      const t = setTimeout(() => resolve("timeout"), Math.max(0, deadline - Date.now()));
      t.unref?.();
    });
    const outcome = await Promise.race([settled, timeout]);
    if (outcome === "timeout") {
      return { ok: false, error: `timed out after ${limits.timeoutMs} ms`, hostCalls, planned: [] };
    }
    if (outcome.error) {
      const err = vm.dump(outcome.error);
      outcome.error.dispose();
      return { ok: false, error: describe(err), hostCalls, planned: [] };
    }
    const json = vm.getString(outcome.value);
    outcome.value.dispose();
    const truncated = json.length > limits.maxResultChars;
    const result = truncated
      ? { truncated_json: json.slice(0, limits.maxResultChars) }
      : (JSON.parse(json) as unknown);
    return { ok: true, result, truncated, hostCalls, planned };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err), hostCalls, planned: [] };
  } finally {
    if (outstanding === 0) {
      vm.dispose();
      runtime.dispose();
    }
    // If host calls are still in flight (timeout), leave disposal to GC; their
    // callbacks check vm.alive before touching the context.
  }
}

function describe(err: unknown): string {
  if (err && typeof err === "object") {
    const o = err as Record<string, unknown>;
    const msg = typeof o["message"] === "string" ? o["message"] : JSON.stringify(o);
    return typeof o["name"] === "string" ? `${o["name"]}: ${msg}` : msg;
  }
  return String(err);
}
