"""End-to-end checks against known, generated Windows artifacts."""
import csv
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.pipeline import Pipeline
from log_hunter.image import open_image
from log_hunter.parser.usb_inventory import usb_device_inventory

spec = importlib.util.spec_from_file_location("synthetic_case", Path(__file__).parent / "fixtures/synthetic_windows_case.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class SyntheticWindowsCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.manifest = fixture.generate(cls.root / "image")
        cls.result = Pipeline().analyze_image(cls.root / "image/synth.E01", cls.root / "analysis")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_reproducible_media_and_unchanged_segments(self):
        other = fixture.generate(self.root / "second")
        self.assertEqual(self.manifest, other)
        for name, digest in self.manifest["segments"].items():
            self.assertEqual(hashlib.sha256((self.root / "image" / name).read_bytes()).hexdigest(), digest)
        with open_image(self.root / "image/synth.E01") as image:
            self.assertEqual(hashlib.sha256(image.read(0, image.size)).hexdigest(), self.manifest["disk_sha256"])
        with self.assertRaises(FileExistsError):
            fixture.generate(self.root / "image")

    def test_all_artifacts_survive_image_extraction(self):
        events = self.result.events
        self.assertTrue({"usb", "prefetch", "lnk", "jumplist", "shellbag", "recyclebin", "history", "tasks", "wlan", "evtx"} <= {e.artifact for e in events})
        self.assertEqual({e.sid for e in events if e.artifact == "lnk"}, set(fixture.SIDS.values()))
        noninfo = [e for e in self.result.errors if e.severity != "info"]
        self.assertEqual(len(noninfo), 1)
        self.assertEqual(noninfo[0].artifact, "taskcache")
        self.assertTrue(noninfo[0].locator.endswith("Actions"))

    def test_usb_known_groups_and_unresolved_reasons(self):
        inventory = usb_device_inventory(self.result.events)
        self.assertEqual(inventory["counts"], self.manifest["expected_usb_counts"])
        for group in inventory["groups"]:
            if group["device_kinds"] == ["unknown"]:
                self.assertTrue(group["unknown_reasons"])

    def test_uuid_placeholders_remain_excluded_in_attached_context(self):
        contexts = [c for e in self.result.events for c in e.details.get("mountpoint_context", [])]
        kinds = {c["uuid_node"]["node_kind"] for c in contexts}
        self.assertTrue({"no_adapter_placeholder", "random_node", "zero_node", "mac_candidate"} <= kinds)
        for context in contexts:
            node = context["uuid_node"]
            if node["node_kind"] != "mac_candidate":
                self.assertIsNone(node["mac_candidate"])
            self.assertFalse(node["mac_is_hardware_confirmed"])
        self.assertFalse(any(e.artifact == "mountpoints2" for e in self.result.events))

    def test_uuid_exclusions_survive_report_and_timeline_exports(self):
        from log_hunter.main import save_result
        output = self.root / "export"
        save_result(self.result, output)
        report = json.loads((output / "report.json").read_text(encoding="utf-8"))
        timeline = json.loads((output / "timeline.json").read_text(encoding="utf-8"))
        with (output / "timeline.csv").open(encoding="utf-8-sig", newline="") as stream:
            csv_details = [json.loads(row["details"]) for row in csv.DictReader(stream)]
        for details in ([e["details"] for e in report["events"]],
                        [e.get("details", {}) for e in timeline], csv_details):
            contexts = [c for d in details for c in d.get("mountpoint_context", [])]
            excluded = [c["uuid_node"] for c in contexts if c["uuid_node"]["node_kind"] != "mac_candidate"]
            self.assertEqual(len(excluded), 12)
            self.assertTrue(all(n["mac_candidate"] is None for n in excluded))
        for name in ("report.json", "timeline.json", "timeline.csv", "report.html"):
            text = (output / name).read_text(encoding="utf-8-sig").casefold()
            self.assertNotIn("80:6e:6f:6e:69:63", text)
        self.assertNotIn("mac_candidate", json.dumps(report["relations"]))

    def test_task_identity_signals_dynamic_times_and_event_candidates(self):
        tasks = {e.details["task_path"]: e for e in self.result.events if e.artifact in ("tasks", "taskcache")}
        self.assertEqual(set(tasks), set(self.manifest["expected_tasks"]))
        expected = {"RegistryOnly": {"xml_not_matched"}, "XmlOnly": {"registry_not_matched"},
                    "Hidden": {"security_descriptor_absent"}, "Mismatch": {"actions_disagree"},
                    "DamagedActions": {"actions_not_decoded"}}
        for namespace, event in tasks.items():
            name = namespace.rsplit("\\", 1)[-1]
            self.assertEqual({s["code"] for s in event.details["task_signals"]}, expected.get(name, set()))
            for field in ("registration_time", "last_run_time", "last_completed_time"):
                self.assertIsNone(event.details.get(field))
            self.assertFalse(event.details["execution_confirmed"])
        for name, size, state in (("Dynamic28", 28, "decoded"), ("Task", 36, "decoded"), ("DynamicOdd", 37, "unsupported_length")):
            dynamic = tasks["\\Demo\\" + name].details["registry_details"]["dynamic_info"]
            self.assertEqual(dynamic["raw"]["size"], size)
            self.assertEqual(dynamic["parse_state"], state)
            self.assertTrue(all(t["meaning"] is None for t in dynamic["time_values"]))
        com = tasks["\\Demo\\Com"].details
        self.assertEqual(com["com_handler_dll"], r"C:\Windows\System32\demo.dll")
        relations = [r for r in self.result.relations if r["type"] == "task_log_correlation"]
        self.assertEqual(len(relations), 5)
        self.assertTrue(all(r["confidence"] == "candidate" and not r["execution_confirmed"] for r in relations))
