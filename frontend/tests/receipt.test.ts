import { describe, expect, it } from "vitest";
import { assertReceipt, checkReceipt } from "../src/lib/receipt";

const good = { statusName: "ACCEPTED", txExecutionResultName: "FINISHED_WITH_RETURN", resultName: "MAJORITY_AGREE" };

describe("checkReceipt (strict finality gate)", () => {
  it("accepts ACCEPTED + FINISHED_WITH_RETURN + MAJORITY_AGREE", () => {
    expect(checkReceipt(good).ok).toBe(true);
  });
  it("accepts FINALIZED", () => {
    expect(checkReceipt({ ...good, statusName: "FINALIZED" }).ok).toBe(true);
  });
  it("accepts numeric protocol status 5 and 7", () => {
    expect(checkReceipt({ ...good, statusName: undefined, status: 5 }).ok).toBe(true);
    expect(checkReceipt({ ...good, statusName: undefined, status: "7" }).ok).toBe(true);
  });
  it("accepts snake_case field names", () => {
    expect(
      checkReceipt({ status_name: "ACCEPTED", tx_execution_result_name: "FINISHED_WITH_RETURN", result_name: "MAJORITY_AGREE" }).ok,
    ).toBe(true);
  });
  it.each(["PENDING", "PROPOSING", "COMMITTING", "REVEALING", "UNDETERMINED", "CANCELED", "LEADER_TIMEOUT", ""])(
    "rejects undecided status %j",
    (statusName) => {
      const v = checkReceipt({ ...good, statusName });
      expect(v.ok).toBe(false);
      expect(v.reason).toMatch(/not decided/);
    },
  );
  it.each(["FINISHED_WITH_ERROR", "ERROR", "NOT_VOTED", ""])("rejects execution %j", (txExecutionResultName) => {
    const v = checkReceipt({ ...good, txExecutionResultName });
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/execution/);
  });
  it.each(["DISAGREE", "MAJORITY_DISAGREE", "TIMEOUT", "NO_MAJORITY", ""])("rejects consensus %j", (resultName) => {
    const v = checkReceipt({ ...good, resultName });
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/consensus/);
  });
  it("rejects a missing receipt", () => {
    expect(checkReceipt(null).ok).toBe(false);
    expect(checkReceipt(undefined).ok).toBe(false);
  });
  it("assertReceipt throws with the label", () => {
    expect(() => assertReceipt("report_target", { ...good, resultName: "DISAGREE" })).toThrow(/report_target: consensus DISAGREE/);
    expect(assertReceipt("x", good).ok).toBe(true);
  });
});
