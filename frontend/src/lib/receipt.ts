/**
 * Strict finality gate. A transaction that merely landed is not a success:
 * it must be decided (ACCEPTED/FINALIZED), the execution must have returned
 * (FINISHED_WITH_RETURN) and the validators must have voted MAJORITY_AGREE.
 */
export interface ReceiptLike {
  statusName?: string;
  status_name?: string;
  status?: number | string;
  txExecutionResultName?: string;
  tx_execution_result_name?: string;
  resultName?: string;
  result_name?: string;
  result?: number | string;
  hash?: string;
}

export interface ReceiptVerdict {
  ok: boolean;
  reason: string | null;
  status: string;
  execution: string;
  consensus: string;
}

const DECIDED = new Set(["ACCEPTED", "FINALIZED"]);
const NUMERIC_STATUS: Record<number, string> = { 5: "ACCEPTED", 7: "FINALIZED" };

export function checkReceipt(r: ReceiptLike | null | undefined): ReceiptVerdict {
  if (!r) return { ok: false, reason: "no receipt", status: "", execution: "", consensus: "" };
  let status = String(r.statusName ?? r.status_name ?? "");
  if (!status && r.status !== undefined) status = NUMERIC_STATUS[Number(r.status)] ?? String(r.status);
  const execution = String(r.txExecutionResultName ?? r.tx_execution_result_name ?? "");
  const consensus = String(r.resultName ?? r.result_name ?? "");
  if (!DECIDED.has(status)) {
    return { ok: false, reason: `not decided (status ${status || "unknown"})`, status, execution, consensus };
  }
  if (execution !== "FINISHED_WITH_RETURN") {
    return { ok: false, reason: `execution ${execution || "unknown"}`, status, execution, consensus };
  }
  if (consensus !== "MAJORITY_AGREE") {
    return { ok: false, reason: `consensus ${consensus || "unknown"}`, status, execution, consensus };
  }
  return { ok: true, reason: null, status, execution, consensus };
}

export function assertReceipt(label: string, r: ReceiptLike | null | undefined): ReceiptVerdict {
  const v = checkReceipt(r);
  if (!v.ok) throw new Error(`${label}: ${v.reason}`);
  return v;
}
