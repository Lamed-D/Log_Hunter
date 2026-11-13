"""Worker shutdown waits for active reads and disposes resources on their owning thread."""
import queue
import threading
import unittest

from log_hunter.ui.jobs import JobRunner


class ShutdownTests(unittest.TestCase):
    def test_shutdown_finishes_active_job_skips_queue_and_closes_on_worker(self):
        runner = JobRunner(queue.Queue())
        started, release, finished = threading.Event(), threading.Event(), threading.Event()
        calls = []

        def active():
            calls.append(('read', threading.get_ident()))
            started.set()
            release.wait(5)

        def close():
            calls.append(('close', threading.get_ident()))
            finished.set()

        runner.submit('active', active)
        self.assertTrue(started.wait(5))
        self.addCleanup(release.set)
        runner.submit('pending', lambda: calls.append(('pending', threading.get_ident())))
        runner.shutdown(close)
        runner.shutdown(close)  # repeated window-close requests cannot duplicate disposal
        self.assertFalse(finished.is_set())
        with self.assertRaises(RuntimeError):
            runner.submit('late', lambda: None)
        release.set()
        self.assertTrue(finished.wait(5))
        runner.thread.join(5)
        self.assertFalse(runner.is_alive())
        self.assertEqual([name for name, _ in calls], ['read', 'close'])
        self.assertEqual(calls[0][1], calls[1][1])
