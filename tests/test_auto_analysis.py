"""Automatic re-analysis: debounce, replacement of older runs, and stopping when no input is left."""
import unittest

from log_hunter.ui.auto_analysis import AutoAnalysis, Superseded


class FakeLoop:
    def __init__(self):
        self.jobs, self.next_id = {}, 0

    def after(self, _ms, fn):
        self.next_id += 1
        self.jobs[self.next_id] = fn
        return self.next_id

    def cancel(self, token):
        self.jobs.pop(token, None)

    def run(self):
        jobs, self.jobs = self.jobs, {}
        for fn in jobs.values():
            fn()


class AutoAnalysisTest(unittest.TestCase):
    def setUp(self):
        self.loop, self.started = FakeLoop(), []
        self.auto = AutoAnalysis(self.loop.after, self.loop.cancel, self.started.append)

    def test_burst_of_changes_starts_one_run(self):
        for _ in range(5):
            self.auto.schedule()
        self.assertTrue(self.auto.waiting)
        self.assertEqual(len(self.loop.jobs), 1)
        self.loop.run()
        self.assertEqual(len(self.started), 1)
        self.assertTrue(self.auto.is_current(self.started[0]))
        self.assertFalse(self.auto.waiting)

    def test_newer_run_makes_older_stop_and_results_stale(self):
        self.auto.run_now()
        old_report = self.auto.guard(1, lambda *a: None)
        self.auto.schedule()
        # The running run is outdated as soon as the inputs change, before the new run starts.
        self.assertFalse(self.auto.is_current(1))
        with self.assertRaises(Superseded):
            old_report(1, 3, "x")
        self.loop.run()
        self.assertEqual(self.started, [1, 2])
        self.assertTrue(self.auto.is_current(2))
        seen = []
        self.auto.guard(2, lambda *a: seen.append(a))(1, 3, "x")
        self.assertEqual(seen, [(1, 3, "x")])

    def test_run_now_replaces_a_waiting_request(self):
        self.auto.schedule()
        self.auto.run_now()
        self.loop.run()
        self.assertEqual(len(self.started), 1)

    def test_stop_drops_waiting_request_and_running_results(self):
        self.auto.run_now()
        self.auto.schedule()
        self.auto.stop()
        self.loop.run()
        self.assertEqual(self.started, [1])
        self.assertFalse(self.auto.is_current(1))


class NoStartButtonTest(unittest.TestCase):
    def test_gui_has_no_start_button(self):
        from pathlib import Path
        source = Path(__file__).resolve().parents[1].joinpath("log_hunter", "ui", "app.py").read_text(encoding="utf-8")
        self.assertNotIn('text="분석 시작"', source)


if __name__ == "__main__":
    unittest.main()
