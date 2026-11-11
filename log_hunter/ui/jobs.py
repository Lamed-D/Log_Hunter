"""One background worker for slow reads (folder listings, file pages); results go to the GUI mailbox."""
import queue
import threading


class JobRunner:
    """Runs submitted functions one at a time on a daemon thread and posts
    ("job", (tag, token, result, error)) to `mailbox`. A newer job with the same tag makes
    older results stale: the GUI compares `token` with `latest(tag)` and drops old ones."""

    def __init__(self, mailbox):
        self.mailbox = mailbox
        self.jobs = queue.Queue()
        self.tokens = {}
        self.lock = threading.Lock()
        threading.Thread(target=self._run, daemon=True).start()

    def submit(self, tag, function, *args):
        with self.lock:
            token = self.tokens.get(tag, 0) + 1
            self.tokens[tag] = token
        self.jobs.put((tag, token, function, args))
        return token

    def latest(self, tag):
        with self.lock:
            return self.tokens.get(tag, 0)

    def _run(self):
        while True:
            tag, token, function, args = self.jobs.get()
            if token != self.latest(tag):
                continue  # superseded before it started
            try:
                self.mailbox.put(("job", (tag, token, function(*args), None)))
            except Exception as exc:  # reported to the user, never kills the worker
                self.mailbox.put(("job", (tag, token, None, str(exc))))
