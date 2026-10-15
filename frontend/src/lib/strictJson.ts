/**
 * Strict JSON reader that preserves the integer/float distinction.
 *
 * `JSON.parse` collapses `2.0` and `2` to the same number, but Python's
 * `json.loads` (what the contract runs) keeps `2.0` a float -- and the
 * contract's schema check rejects floats. To keep the Threat Radar's verdict
 * identical to the contract's, numbers are classified by their *literal*:
 *
 *   - integer literal            -> number (safe range) or bigint (beyond it)
 *   - literal with . / e / E     -> FloatLiteral (never an integer)
 *
 * Anything JSON.parse or json.loads would reject (trailing commas, NaN,
 * leading zeros, raw control characters, BOM, trailing garbage) throws.
 */
export class FloatLiteral {
  constructor(readonly text: string) {}
}

export type JsonValue =
  | null
  | boolean
  | number
  | bigint
  | FloatLiteral
  | string
  | JsonValue[]
  | { [k: string]: JsonValue };

const MAX_DEPTH = 64;
const WS = new Set([" ", "\t", "\n", "\r"]);

export function parseStrictJson(text: string): JsonValue {
  let i = 0;

  const fail = (msg: string): never => {
    throw new SyntaxError(`${msg} at ${i}`);
  };
  const skip = () => {
    while (i < text.length && WS.has(text[i])) i++;
  };

  function str(): string {
    i++; // opening quote
    let out = "";
    for (;;) {
      if (i >= text.length) fail("unterminated string");
      const c = text[i];
      const code = text.charCodeAt(i);
      if (c === '"') {
        i++;
        return out;
      }
      if (code < 0x20) fail("control character in string");
      if (c === "\\") {
        const n = text[i + 1];
        i += 2;
        const simple: Record<string, string> = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
        if (n in simple) out += simple[n];
        else if (n === "u") {
          const hex = text.slice(i, i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail("bad unicode escape");
          out += String.fromCharCode(parseInt(hex, 16));
          i += 4;
        } else fail("bad escape");
      } else {
        out += c;
        i++;
      }
    }
  }

  function num(): JsonValue {
    const m = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/.exec(text.slice(i));
    if (!m) return fail("bad number");
    const lit = m[0];
    i += lit.length;
    if (m[2] !== undefined || m[3] !== undefined) return new FloatLiteral(lit);
    const big = BigInt(lit);
    return big >= BigInt(Number.MIN_SAFE_INTEGER) && big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big;
  }

  function value(depth: number): JsonValue {
    if (depth > MAX_DEPTH) fail("too deep");
    skip();
    const c = text[i];
    if (c === "{") {
      i++;
      const obj: { [k: string]: JsonValue } = {};
      skip();
      if (text[i] === "}") {
        i++;
        return obj;
      }
      for (;;) {
        skip();
        if (text[i] !== '"') fail("expected key");
        const k = str();
        skip();
        if (text[i] !== ":") fail("expected colon");
        i++;
        obj[k] = value(depth + 1); // duplicate keys: last wins (as in Python)
        skip();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "}") {
          i++;
          return obj;
        }
        fail("expected , or }");
      }
    }
    if (c === "[") {
      i++;
      const arr: JsonValue[] = [];
      skip();
      if (text[i] === "]") {
        i++;
        return arr;
      }
      for (;;) {
        arr.push(value(depth + 1));
        skip();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "]") {
          i++;
          return arr;
        }
        fail("expected , or ]");
      }
    }
    if (c === '"') return str();
    if (text.startsWith("true", i)) {
      i += 4;
      return true;
    }
    if (text.startsWith("false", i)) {
      i += 5;
      return false;
    }
    if (text.startsWith("null", i)) {
      i += 4;
      return null;
    }
    if (c === "-" || (c >= "0" && c <= "9")) return num();
    return fail("unexpected token");
  }

  const v = value(0);
  skip();
  if (i !== text.length) fail("trailing characters");
  return v;
}
