"""Synthetic task registrations and definition identity boundaries."""
import hashlib
import struct
import tempfile
import unittest
import uuid
from pathlib import Path

from test_example_samples import load_demo
from log_hunter.parser.taskcache import TaskCacheParser, ROOT, actions_info, dynamic_info
from log_hunter.parser.tasks import TaskSchedulerParser
from log_hunter.core.task_merge import merge_tasks, task_log_relations
from log_hunter.core.correlation import correlate
from log_hunter.core.models import ForensicEvent

GUID = "{11111111-2222-3333-4444-555555555555}"
CLSID = "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}"
STAMP = 133485408000000000


def string(value):
    raw = value.encode("utf-16-le")
    return struct.pack("<I", len(raw)) + raw


def actions(command="C:\\Windows\\System32\\cmd.exe", com=False):
    prefix = struct.pack("<H", 3) + string("Author")
    if com:
        return prefix + struct.pack("<H", 0x7777) + string("") + uuid.UUID(CLSID).bytes_le + string("")
    return prefix + struct.pack("<H", 0x6666) + string("") + string(command) + string("/c exit") + string("")


def hive_bytes(sd=True, com=False, namespace="\\Demo\\Task", tree_namespace=None, bad_actions=False):
    b = load_demo().HiveBuilder()
    tree = {}

    def put(path, values):
        node = tree
        for part in path.split("\\"):
            node = node.setdefault(part, {})
        node[":values"] = values

    def text(name, value):
        return name, 1, (value + "\0").encode("utf-16-le")

    put(ROOT + "\\Tasks\\" + GUID, [text("Path", namespace),
        ("DynamicInfo", 3, struct.pack("<IQQIIQ", 3, STAMP, STAMP, 0, 0, STAMP)),
        ("Actions", 3, b"bad" if bad_actions else actions(com=com))])
    put(ROOT + "\\Tree" + (tree_namespace or namespace), [text("Id", GUID),
        ("Index", 4, struct.pack("<I", 1))] + ([("SD", 3, b"synthetic-sd")] if sd else []))
    for catalog in ("Boot", "Logon", "Plain", "Maintenance"):
        put(ROOT + "\\" + catalog + "\\" + GUID, [])
    if com:
        put("Classes\\CLSID\\" + CLSID + "\\InprocServer32", [text("", "C:\\Users\\alice\\demo.dll")])

    def build(name, node):
        children = [build(k, v) for k, v in node.items() if k != ":values"]
        return b.key(name, STAMP, node.get(":values", []), children)
    return b.build(build("ROOT", tree))


def xml_bytes(command="C:\\Windows\\System32\\cmd.exe", multiple=False):
    action = f"<Exec><Command>{command}</Command><Arguments>/c exit</Arguments></Exec>"
    return (f'<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
            '<Principals><Principal id="Other"><UserId>bob</UserId></Principal>'
            '<Principal id="Author"><UserId>alice</UserId></Principal></Principals>'
            f'<Actions Context="Author">{action}{action if multiple else ""}</Actions></Task>').encode()


class TaskCacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.windows = Path(self.tmp.name) / "Windows"

    def registry(self, **kwargs):
        path = self.windows / "System32/config/SOFTWARE"
        path.parent.mkdir(parents=True, exist_ok=True)
        data = hive_bytes(**kwargs)
        path.write_bytes(data)
        parser = TaskCacheParser()
        events = list(parser.parse(path))
        if kwargs.get("bad_actions"):
            self.assertTrue(parser.errors)
            self.assertTrue(all(e.severity == "warning" for e in parser.errors))
        else:
            self.assertEqual(parser.errors, [])
        self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), hashlib.sha256(data).digest())
        return events

    def xml(self, namespace="Demo/Task", **kwargs):
        path = self.windows / "System32/Tasks" / namespace
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(xml_bytes(**kwargs))
        parser = TaskSchedulerParser()
        events = list(parser.parse(path))
        self.assertEqual(parser.errors, [])
        return events

    def test_normal_merge_preserves_both_sources_and_xml_principal(self):
        result = merge_tasks(self.registry() + self.xml())
        self.assertEqual(len(result), 1)
        d = result[0].details
        self.assertEqual(result[0].artifact, "tasks")
        self.assertEqual(d["task_guid"], GUID)
        self.assertEqual(d["run_user"], "alice")
        self.assertEqual({s["kind"] for s in d["task_sources"]}, {"registry", "xml"})
        self.assertEqual(len(d["xml_details"]), 1)
        self.assertEqual(d["task_signals"], [])
        self.assertEqual(d["launch_catalogs"], ["Boot", "Logon", "Plain", "Maintenance"])
        self.assertIsNone(d["last_run_time"])
        self.assertFalse(d["time_semantics_verified"])

    def test_one_sided_observations_are_signals(self):
        for events, code in ((self.registry(), "xml_not_matched"), (self.xml(), "registry_not_matched")):
            result = merge_tasks(events)
            self.assertEqual(len(result), 1)
            self.assertIn(code, [s["code"] for s in result[0].details["task_signals"]])
            self.assertFalse(result[0].details["execution_confirmed"])

    def test_missing_sd_and_command_disagreement(self):
        result = merge_tasks(self.registry(sd=False) + self.xml(command="C:\\Windows\\System32\\other.exe"))
        codes = {s["code"] for s in result[0].details["task_signals"]}
        self.assertEqual(codes, {"security_descriptor_absent", "actions_disagree"})

    def test_working_directory_disagreement_is_an_action_signal(self):
        for registered, definition, disagrees in (
                (r"C:\Evidence\registered", r"C:\Evidence\definition", True),
                (r"C:\Evidence", "", True),
                (r"C:\Evidence", r"c:\evidence", False),
                ("", "", False)):
            with self.subTest(registered=registered, definition=definition):
                registrations = self.registry()
                registrations[0].details["registry_details"]["actions"]["actions"][0]["working_directory"] = registered
                definitions = self.xml()
                definitions[0].details["working_directory"] = definition
                result = merge_tasks(registrations + definitions)
                codes = {s["code"] for s in result[0].details["task_signals"]}
                self.assertEqual("actions_disagree" in codes, disagrees)
                self.assertEqual(result[0].details["xml_details"][0]["working_directory"], definition)

    def test_com_handler_resolves_recorded_dll(self):
        d = self.registry(com=True)[0].details
        action = d["registry_details"]["actions"]["actions"][0]
        self.assertEqual(action["class_id"], CLSID)
        self.assertEqual(action["com_handler_dll"], "C:\\Users\\alice\\demo.dll")
        self.assertIn("com_dll_outside_system_path", [s["code"] for s in d["task_signals"]])

    def test_dynamic_lengths_preserve_unknown_time_semantics(self):
        for size in (28, 36):
            raw = struct.pack("<IQQII", 3, STAMP, STAMP, 0, 0) + (struct.pack("<Q", STAMP) if size == 36 else b"")
            d = dynamic_info(raw)
            self.assertEqual(d["raw"]["size"], size)
            self.assertEqual(len(d["time_values"]), 2 if size == 28 else 3)
            self.assertTrue(all(t["meaning"] is None for t in d["time_values"]))
        self.assertEqual(dynamic_info(b"x")["parse_state"], "unsupported_length")
        self.assertEqual(dynamic_info(b"\0" * 28)["parse_state"], "unsupported_version")

    def test_damaged_actions_do_not_discard_registration(self):
        self.assertEqual(len(self.registry(bad_actions=True)), 1)
        for raw in (actions()[:-1], struct.pack("<H", 3) + struct.pack("<I", 0xffffffff)):
            self.assertEqual(actions_info(raw)["parse_state"], "damaged")

    def test_different_folders_and_inconsistent_identity_stay_separate(self):
        self.assertEqual(len(merge_tasks(self.registry() + self.xml("Other/Task"))), 2)
        self.assertEqual(len(merge_tasks(self.registry(tree_namespace="\\Other\\Task") + self.xml())), 2)

    def test_different_windows_roots_do_not_merge(self):
        registry, xml = self.registry(), self.xml()
        xml[0].source = xml[0].source.replace("Windows", "OtherWindows")
        self.assertEqual(len(merge_tasks(registry + xml)), 2)

    def test_multiple_actions_form_one_definition(self):
        result = merge_tasks(self.xml(multiple=True))
        self.assertEqual(len(result), 1)
        self.assertEqual(len(result[0].details["xml_details"]), 2)

    def test_scheduler_events_are_scoped_path_candidates(self):
        events = merge_tasks(self.registry() + self.xml())
        for event_id in (106, 141):
            events.append(ForensicEvent("evtx", str(self.windows / "System32/winevt/Logs/task.evtx"), "event",
                details={"provider": "Microsoft-Windows-TaskScheduler", "event_id": event_id,
                         "event_data": {"TaskName": "\\Demo\\Task", "TaskInstanceId": CLSID}}))
        relations = [r for r in correlate(events) if r["type"] == "task_log_correlation"]
        self.assertEqual(len(relations), 2)
        for r in relations:
            self.assertFalse(r["execution_confirmed"])
            self.assertTrue(r["evidence_details"]["comparisons"][0]["matched"])
        self.assertEqual(task_log_relations(events, 1)[0]["candidate_count"], 2)
        events[-1].details["event_data"]["TaskName"] = "\\Other\\Task"
        self.assertEqual(len(task_log_relations(events)), 1)

    def test_log_recovery_keeps_original_source_and_hash(self):
        from unittest.mock import patch
        from log_hunter.core.pipeline import Pipeline
        registry = self.registry()
        xml = self.xml()
        source = Path(registry[0].source)
        clean = source.read_bytes()
        dirty = bytearray(clean)
        struct.pack_into("<II", dirty, 4, 2, 1)
        source.write_bytes(dirty)
        sidecar = Path(str(source) + ".LOG1")
        sidecar.write_bytes(b"synthetic-log-placeholder")
        with patch("log_hunter.core.pipeline.replay_logs", return_value=(clean, {"recovered": True})) as replay:
            result = Pipeline().analyze([("taskcache", source), ("tasks", Path(xml[0].source))])
        replay.assert_called_once_with(source)
        self.assertEqual(len(result.events), 1)
        self.assertTrue(all(s["sha256"] for s in result.events[0].details["task_sources"]))
        self.assertEqual({s["source"] for s in result.events[0].details["task_sources"]}, {str(source), xml[0].source})
        self.assertIn(str(sidecar), [e.source for e in result.evidence])
        self.assertEqual(source.read_bytes(), dirty)

    def test_ambiguous_registration_and_isolated_sources_never_merge(self):
        import copy
        first = self.registry()[0]
        second = copy.deepcopy(first)
        second.details["task_guid"] = CLSID
        self.assertEqual(len(merge_tasks([first, second] + self.xml())), 3)
        first.source = "SOFTWARE"
        self.assertEqual(len(merge_tasks([first] + self.xml())), 2)

    def test_action_bounds_optional_com_data_and_multiple_exec(self):
        raw = actions()
        second = raw[2 + 4 + len("Author".encode("utf-16-le")):]
        self.assertEqual(len(actions_info(raw + second)["actions"]), 2)
        self.assertEqual(actions_info(actions(com=True)[:-4])["parse_state"], "decoded")
        self.assertEqual(actions_info(b"\x04\0")["parse_state"], "unsupported")
        self.assertEqual(actions_info(b"\x03\0" + struct.pack("<I", 3) + b"abc")["parse_state"], "damaged")

    def test_pipeline_tasks_directory_includes_nested_definitions(self):
        from log_hunter.core.pipeline import Pipeline
        registration = self.registry()[0]
        self.xml()
        result = Pipeline().analyze([("taskcache", Path(registration.source)),
                                     ("tasks", self.windows / "System32/Tasks")])
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].artifact, "tasks")
        self.assertEqual(len(result.events[0].details["task_sources"]), 2)


if __name__ == "__main__":
    unittest.main()
