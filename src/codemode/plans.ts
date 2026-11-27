/**
 * Plan-then-commit store for gated issuance. Plans live in memory for a short
 * time; committing one requires a human to approve it through MCP elicitation.
 */
import { createHash, randomUUID } from "node:crypto";
import type { PlannedIssue } from "./sandbox.js";

export interface Plan {
  id: string;
  digest: string;
  items: PlannedIssue[];
  createdAt: number;
  committed: boolean;
}

const TTL_MS = 30 * 60 * 1000;

export class PlanStore {
  private plans = new Map<string, Plan>();

  create(items: PlannedIssue[]): Plan {
    this.sweep();
    const digest = createHash("sha256").update(JSON.stringify(items)).digest("hex");
    const plan: Plan = { id: randomUUID(), digest, items, createdAt: Date.now(), committed: false };
    this.plans.set(plan.id, plan);
    return plan;
  }

  get(id: string): Plan | undefined {
    this.sweep();
    return this.plans.get(id);
  }

  markCommitted(id: string): void {
    const p = this.plans.get(id);
    if (p) p.committed = true;
  }

  private sweep(): void {
    const now = Date.now();
    for (const [id, p] of this.plans) {
      if (now - p.createdAt > TTL_MS) this.plans.delete(id);
    }
  }
}
