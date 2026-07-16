#!/usr/bin/env python3

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from normalize import CLIENTS, NormalizationError, clean_request, normalize, normalize_client


class NormalizerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = Path(__file__).with_name("observations.json")
        cls.observations = json.loads(cls.source.read_text(encoding="utf-8"))

    def test_two_normalizations_are_byte_identical_and_manifest_digests_match(self) -> None:
        with tempfile.TemporaryDirectory() as first_name, tempfile.TemporaryDirectory() as second_name:
            first = Path(first_name)
            second = Path(second_name)
            normalize(self.source, first)
            normalize(self.source, second)
            first_files = {path.name: path.read_bytes() for path in first.iterdir()}
            second_files = {path.name: path.read_bytes() for path in second.iterdir()}
            self.assertEqual(first_files, second_files)
            manifest = json.loads(first_files["manifest.json"])
            for entry in manifest["files"]:
                self.assertEqual(hashlib.sha256(first_files[entry["path"]]).hexdigest(), entry["sha256"])

    def test_unknown_root_and_nested_fields_fail_closed(self) -> None:
        hostile = copy.deepcopy(self.observations)
        hostile["unknown"] = "value"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(NormalizationError):
                normalize(self._write_source(hostile, Path(directory)), Path(directory) / "out")

        client = copy.deepcopy(self.observations["clients"][0])
        client["approle"]["requests"][0]["body_shape"]["credential_output"] = "string"
        with self.assertRaises(NormalizationError):
            normalize_client(client, CLIENTS[0])

    def test_headers_are_case_folded_deduplicated_and_hostile_values_refuse(self) -> None:
        request = copy.deepcopy(self.observations["clients"][0]["paths"][0]["requests"][0])
        request["header_names"].extend(["X-Vault-Token", "x-vault-token"])
        cleaned = clean_request(request)
        self.assertEqual(cleaned["header_names"].count("x-vault-token"), 1)
        request["header_names"].append("cookie")
        with self.assertRaises(NormalizationError):
            clean_request(request)

    def test_urls_host_paths_usernames_tls_and_credential_output_refuse(self) -> None:
        mutations = []
        url = copy.deepcopy(self.observations["clients"][0])
        url["paths"][0]["requests"][0]["query_keys"] = ["https://capture.invalid/user"]
        mutations.append((url, CLIENTS[0]))
        host_path = copy.deepcopy(self.observations["clients"][0])
        host_path["tls_root"] = "/home/capture/private-ca.pem"
        mutations.append((host_path, CLIENTS[0]))
        tls = copy.deepcopy(self.observations["clients"][0])
        tls["tls_root"] = "-----BEGIN PRIVATE KEY-----"
        mutations.append((tls, CLIENTS[0]))
        command = copy.deepcopy(self.observations["clients"][2])
        command["subprocess_argv"][0][3] = "OLSS_SYNTHETIC_TOKEN_7d9f3c2a1b8e6d4f"
        mutations.append((command, CLIENTS[2]))
        for value, expected in mutations:
            with self.subTest(expected=expected):
                with self.assertRaises(NormalizationError):
                    normalize_client(value, expected)

    @staticmethod
    def _write_source(value: object, directory: Path) -> Path:
        path = directory / "source.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path


if __name__ == "__main__":
    unittest.main()
