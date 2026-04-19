import { describe, expect, it } from "vitest";

import { formatMs, formatPercent } from "@/lib/utils";

describe("format helpers", () => {
  it("formats percentages", () => {
    expect(formatPercent(0.412)).toBe("41%");
  });

  it("formats millisecond values", () => {
    expect(formatMs(12.345)).toBe("12.3 ms");
  });
});
