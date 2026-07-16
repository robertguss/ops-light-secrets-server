#!/usr/bin/env python3
"""Replay the stable contract from retained client-trace fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from normalize import CLIENTS
from replay import FAULT_COUNTS, PATH_CASES, SENTINELS, check


def contains_key(value: object, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(contains_key(item, key) for item in value.values())
    if isinstance(value, list):
        return any(contains_key(item, key) for item in value)
    return False


def validate(directory: Path) -> None:
    manifest_bytes = (directory / "manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    check(set(manifest) == {"schema", "tool_version", "source_schema", "provenance", "files"},
          "manifest schema")
    check(manifest["schema"] == 1 and manifest["tool_version"] == "client-trace-normalizer-v1",
          "manifest version")
    expected_names = [f"{name}-{backend or 'direct'}.json" for name, backend in CLIENTS]
    check([entry["path"] for entry in manifest["files"]] == expected_names, "fixture inventory")
    fixtures = []
    for entry, expected in zip(manifest["files"], CLIENTS, strict=True):
        content = (directory / entry["path"]).read_bytes()
        check(hashlib.sha256(content).hexdigest() == entry["sha256"], "fixture digest")
        text = content.decode("utf-8")
        check(all(sentinel not in text for sentinel in SENTINELS), "fixture sentinel")
        fixture = json.loads(text)
        check(not contains_key(fixture, "duration_ms"), "nondeterministic duration retained")
        check((fixture["client"], fixture["backend"]) == (expected[0], expected[1] or "direct"),
              "fixture identity")
        check(fixture["token_supply"] == "VAULT_TOKEN" and fixture["tls_root"] == "VAULT_CACERT",
              "credential supply")
        check([item["case"] for item in fixture["paths"]] == PATH_CASES, "path matrix")
        check({item["scenario"]: item["request_count"] for item in fixture["faults"]}
              == FAULT_COUNTS, "fault replay")
        for fault in fixture["faults"]:
            check(fault["routes"] == [request["route"] for request in fault["requests"]],
                  "fault request replay")
        fixtures.append(fixture)

    direct_paths = {item["case"]: item["requests"] for item in fixtures[0]["paths"]}
    check(direct_paths == {item["case"]: item["requests"] for item in fixtures[1]["paths"]},
          "direct wire replay")
    for fixture in fixtures[:2]:
        check(fixture["approle"]["process"]["exit_status"] == 0, "AppRole replay")
        check({item["probe"]: [request["route"] for request in item["requests"]]
               for item in fixture["probes"]} == {
                   "seal-status": ["seal-status", "leader"],
                   "health": ["health"],
                   "lookup-self": ["lookup-self"],
               }, "probe replay")
    for fixture in fixtures[2:]:
        check(len(fixture["subprocess_argv"]) == 14, "fnox subprocess replay")
        emitted = {item["case"]: item["requests"] for item in fixture["paths"] if item["requests"]}
        check(emitted == {case: direct_paths[case] for case in emitted}, "fnox wire replay")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixtures", type=Path)
    args = parser.parse_args()
    validate(args.fixtures)
    print(json.dumps({"schema": 1, "event": "fixture_replay_pass", "clients": 6}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
