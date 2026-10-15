"""Golden-vector side of the Python <-> TypeScript feed-parser parity check.

`tests/vectors/feed_parity.json` is consumed by BOTH this test (against the
contract's `_source_from_response`) and `frontend/tests/parity.test.ts` (against
`classifyResponse`). Both must produce the recorded `expect`/`tier` for every
vector, so the two implementations agree with each other by construction."""

import json
import pathlib

import pytest

VEC = json.loads((pathlib.Path(__file__).parent / "vectors" / "feed_parity.json").read_text())


@pytest.mark.parametrize("v", VEC["vectors"], ids=[v["name"] for v in VEC["vectors"]])
def test_contract_matches_golden_vector(pg, mod, v):
    body = v["body"].encode("utf-8")  # production bodies are bytes
    out = mod._source_from_response(v["status"], body, VEC["target"], VEC["max_ts"])
    assert out["k"] == v["expect"]
    if v["expect"] == "OK":
        assert out["rec"]["tier"] == v["tier"]
