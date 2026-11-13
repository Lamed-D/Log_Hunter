"""예약 작업 screen: basic columns, detail and source comparison tabs, signal filter, report tab (synthetic values)."""
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.models import ForensicEvent
from log_hunter.core.pipeline import AnalysisResult
from log_hunter.core.tree import build_tree, matches
from log_hunter.main import save_result
from log_hunter.ui import columns, record_fields, task_view


def merged(**over):
    """A task merged from the registry and its task file, in the engine contract's shape."""
    details = {
        "task_name": "Updater", "task_path": r"\Example\Updater", "task_guid": "{00000000-0000-0000-0000-00000000000A}",
        "command": r"C:\Users\alice\AppData\Local\updater.exe", "arguments": "--quiet", "run_user": "alice",
        "registration_time": "2024-01-01T10:00:00+00:00", "last_run_time": "2024-01-02T09:00:00+00:00",
        "last_completed_time": None, "hidden_indicator": True,
        "task_sources": [{"kind": "registry", "source": r"C:\Evidence\SOFTWARE", "locator": "TaskCache", "sha256": "a" * 64},
                         {"kind": "xml", "source": r"C:\Evidence\Tasks\Example\Updater", "locator": "file", "sha256": "b" * 64}],
        "task_signals": [{"code": "hidden_task", "reason": "SD missing", "evidence": "Tree SD 값 없음"},
                         {"code": "command_mismatch", "reason": "differs", "evidence": None}],
        "xml_details": {"author": "alice", "command": r"C:\Users\alice\AppData\Local\updater.exe",
                        "triggers": [{"type": "LogonTrigger"}, {"type": "BootTrigger"}]},
        "registry_details": {"command": r"C:\Users\alice\AppData\Local\other.exe", "sd_present": False, "dynamic_info": "03000000"},
        "execution_confirmed": False, "time_semantics_verified": False,
    }
    details.update(over)
    return ForensicEvent("tasks", r"C:\Evidence\SOFTWARE", "task_definition", details=details)


class TaskViewTest(unittest.TestCase):
    def test_basic_cells(self):
        shown = {key: task_view.cell(key, merged()) for key in task_view.COLUMNS}
        self.assertEqual(shown["task_name"], r"\Example\Updater")
        self.assertEqual(shown["task_command"], r"C:\Users\alice\AppData\Local\updater.exe --quiet")
        self.assertEqual(shown["registration_time"], "2024-01-01 10:00:00 (UTC)")
        self.assertEqual(shown["last_completed_time"], "알 수 없음")
        self.assertEqual(shown["task_hidden"], "숨겨진 작업 단서 (보안 설명자 없음)")
        self.assertEqual(shown["task_source"], "레지스트리·작업 파일 둘 다")
        self.assertEqual(shown["task_signals"], "⚠ 숨겨진 작업; 명령이 서로 다름 (확정 아님)")
        registry_only = merged(task_sources=[{"kind": "registry", "source": "SOFTWARE"}], task_signals=[], hidden_indicator=None,
                               com_handler_dll=r"C:\Example\handler.dll", com_handler_uuid="{CLSID}")
        self.assertEqual(task_view.cell("task_source", registry_only), "레지스트리만 (작업 파일 없음, 등록만 남음)")
        self.assertEqual(task_view.cell("task_command", registry_only), r"COM 처리기: C:\Example\handler.dll {CLSID}")
        self.assertEqual(task_view.cell("task_hidden", registry_only), "알 수 없음")
        self.assertEqual(task_view.cell("task_signals", registry_only), "")

    def test_detail_and_compare(self):
        text = "\n".join(task_view.detail_lines(merged()))
        self.assertIn("로그온 시, 부팅 시", text)
        self.assertIn("SHA-256 " + "a" * 64, text)
        self.assertIn("실제 실행을 확정하지 않습니다", text)
        self.assertIn("⚠ 숨겨진 작업 — Tree SD 값 없음", text)
        rows = {r[0]: r for r in task_view.compare_rows(merged())}
        self.assertEqual(rows["명령"][3], "다름")
        self.assertEqual(rows["작성자"][3], "작업 파일에만")
        self.assertEqual(task_view.compare_rows(merged(registry_details=None)), [])

    def test_tree_filter_columns_and_properties(self):
        plain = merged(task_signals=[], task_path=r"\Example\Plain")
        run = ForensicEvent("run", r"C:\Evidence\NTUSER.DAT", "autorun", details={})
        events = [merged(), plain, run]
        autostart = next(c for c in build_tree(events)[1].children if c.key == "art:autostart")
        tasks = next(c for c in autostart.children if "tasks" in c.value)
        signal = tasks.children[0]
        self.assertEqual(signal.text, "의심 신호만 보기 (1)")
        self.assertEqual([e for e in events if matches(signal, e, None)], [events[0]])
        self.assertEqual([c.key for c in columns.columns_for(tasks)][:3], ["registration_time", "task_name", "task_command"])
        self.assertEqual(columns.columns_for(signal), columns.CATEGORY_COLUMNS["scheduled_tasks"])
        props = record_fields.properties(merged())
        self.assertEqual([name for name, _l, _s in props.tabs], ["예약 작업 상세", "출처 비교", "원본 JSON"])
        self.assertEqual(dict(props.fields)["출처"], "레지스트리·작업 파일 둘 다")

    def test_current_task_file_records(self):
        event = ForensicEvent("tasks", r"C:\Evidence\Tasks\Backup", "suspicious_task", details={
            "task_name": "Backup", "uri": r"\Backup", "command": "powershell.exe", "arguments": "-enc AAAA",
            "principal": {"user_id": "S-1-5-18"}, "registration_date": "2024-01-01T10:00:00",
            "suspicion_flags": ["encoded_command"], "settings": {"hidden": "true"}})
        shown = {key: task_view.cell(key, event) for key in task_view.COLUMNS}
        self.assertEqual(shown["task_name"], r"\Backup")
        self.assertEqual(shown["run_user"], "S-1-5-18")
        self.assertEqual(shown["registration_time"], "2024-01-01 10:00:00 (시간대 미상)")
        self.assertEqual(shown["task_hidden"], "작업 파일에 숨김 설정")
        self.assertEqual(shown["task_source"], "작업 파일")
        self.assertIn("인코딩된 명령", shown["task_signals"])

    def engine_records(self):
        """Real parser + merge output: a merged task with a different registered command and no SD, plus a registration
        whose task file is missing (artifact `taskcache`)."""
        from log_hunter.core.task_merge import merge_tasks
        from log_hunter.parser.taskcache import TaskCacheParser
        from log_hunter.parser.tasks import TaskSchedulerParser
        from test_taskcache import hive_bytes, xml_bytes
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        windows = Path(temp.name) / "Windows"
        (windows / "System32/config").mkdir(parents=True)
        (windows / "System32/Tasks/Demo").mkdir(parents=True)
        software, task = windows / "System32/config/SOFTWARE", windows / "System32/Tasks/Demo/Task"
        software.write_bytes(hive_bytes(sd=False))
        task.write_bytes(xml_bytes(command=r"C:\Windows\System32\other.exe"))
        merged_task = merge_tasks(list(TaskCacheParser().parse(software)) + list(TaskSchedulerParser().parse(task)))
        software.write_bytes(hive_bytes(namespace=r"\Demo\RegOnly"))
        registration = merge_tasks(list(TaskCacheParser().parse(software)))
        return merged_task[0], registration[0], str(software), str(task)

    def test_engine_shape_compare_detail_and_signals(self):
        merged_task, registration, software, task = self.engine_records()
        self.assertEqual((merged_task.artifact, registration.artifact), ("tasks", "taskcache"))
        rows = {r[0]: r for r in task_view.compare_rows(merged_task)}
        self.assertEqual(rows["동작 1 명령"][1:], (r"C:\Windows\System32\cmd.exe", r"C:\Windows\System32\other.exe", "다름"))
        self.assertEqual(rows["작업 경로"][3], "같음")
        self.assertEqual(rows["실행 컨텍스트"][1:], ("Author", "Author", "같음"))
        shown = task_view.cell("task_signals", merged_task)
        self.assertIn("보안 설명자 없음 (숨겨진 작업 단서)", shown)
        self.assertIn("등록 정보와 작업 파일의 동작이 서로 다름", shown)
        self.assertNotRegex(shown, "[A-Za-z]{4,}")  # no engine reason sentences in English
        origin = {software: r"[case.E01] 볼륨 0\Windows\System32\config\SOFTWARE"}
        text = "\n".join(task_view.detail_lines(merged_task, lambda p: origin.get(p, p)))
        self.assertIn(r"레지스트리: [case.E01] 볼륨 0\Windows\System32\config\SOFTWARE · SHA-256", text)
        self.assertIn("보안 설명자 없음", text)
        self.assertIn("어떤 시각인지 확인되지 않음", text)
        self.assertIn(r"동작 1: 종류 Exec · 명령 C:\Windows\System32\cmd.exe", text)
        self.assertNotIn("hex_preview", text)  # raw blobs stay in the raw JSON tab
        # registration without a task file: same columns, its signal in Korean, nothing claimed from a task file
        self.assertEqual(task_view.cell("task_source", registration), "레지스트리만 (작업 파일 없음, 등록만 남음)")
        self.assertIn("작업 파일 없음", task_view.cell("task_signals", registration))
        self.assertEqual(task_view.compare_rows(registration), [])
        self.assertIn("[작업 파일 정보]\n  알 수 없음", "\n".join(task_view.detail_lines(registration)))

    def test_registrations_share_the_task_node_filter_and_report(self):
        merged_task, registration, _software, _task = self.engine_records()
        run = ForensicEvent("run", r"C:\Evidence\NTUSER.DAT", "autorun", details={})
        events = [merged_task, registration, run]
        autostart = next(c for c in build_tree(events)[1].children if c.key == "art:autostart")
        self.assertEqual([c.label for c in autostart.children],
                         ["자동 실행 프로그램", "시작프로그램 폴더", "백그라운드 서비스", "예약된 작업"])
        tasks = next(c for c in autostart.children if "tasks" in c.value)
        self.assertEqual(tasks.count, 2)
        self.assertEqual([e for e in events if matches(tasks, e, None)], [merged_task, registration])
        self.assertEqual(tasks.children[0].text, "의심 신호만 보기 (2)")
        self.assertEqual(columns.columns_for(tasks), columns.CATEGORY_COLUMNS["scheduled_tasks"])
        props = record_fields.properties(registration)
        self.assertEqual([name for name, _l, _s in props.tabs], ["예약 작업 상세", "출처 비교", "원본 JSON"])
        with tempfile.TemporaryDirectory() as temp:
            save_result(AnalysisResult(events=[registration]), Path(temp) / "out")
            page = (Path(temp) / "out" / "report.html").read_text(encoding="utf-8")
        self.assertIn(r"<details><summary>\Demo\RegOnly</summary>", page)

    def test_report_tab(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "out"
            save_result(AnalysisResult(events=[merged(arguments="<script>x</script>")]), out)
            page = (out / "report.html").read_text(encoding="utf-8")
            self.assertIn('data-panel="tasks">예약 작업', page)
            self.assertIn(r"<details><summary>\Example\Updater</summary>", page)
            self.assertIn("&lt;script&gt;x&lt;/script&gt;", page)
            plain = Path(temp) / "plain"
            save_result(AnalysisResult(events=[]), plain)
            self.assertNotIn('data-panel="tasks"', (plain / "report.html").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
