"""Automatic re-analysis: changes to the input list are gathered briefly, then one run starts; a newer run replaces an older one."""


class Superseded(Exception):
    """Raised inside an older run's progress callback so it stops once a newer run has started."""


class AutoAnalysis:
    """Debounce and generation bookkeeping, free of Tk so it can be tested.

    `after(ms, fn)` / `cancel(token)` schedule on the UI loop; `start(generation)` begins a run.
    Results carry their generation, and only the newest generation's result is used.
    """

    def __init__(self, after, cancel, start, delay_ms=400):
        self._after, self._cancel, self._start, self.delay_ms = after, cancel, start, delay_ms
        self._pending = None
        self.generation = 0

    def schedule(self):
        """Ask for a run soon; several requests inside the delay become one run.
        A run already going is outdated at once: it stops at its next progress report."""
        if self._pending is not None:
            self._cancel(self._pending)
        self.generation += 1
        self._pending = self._after(self.delay_ms, self._fire)

    def run_now(self):
        if self._pending is not None:
            self._cancel(self._pending)
            self._pending = None
        self.generation += 1
        self._fire()

    def stop(self):
        """Drop any waiting request and make every running run stale (used when nothing is left to analyze)."""
        if self._pending is not None:
            self._cancel(self._pending)
            self._pending = None
        self.generation += 1

    def _fire(self):
        self._pending = None
        self._start(self.generation)

    @property
    def waiting(self):
        return self._pending is not None

    def is_current(self, generation):
        return generation == self.generation

    def guard(self, generation, progress):
        """Wrap a progress callback so an outdated run stops at its next progress report."""
        def report(*args):
            if generation != self.generation:
                raise Superseded()
            progress(*args)
        return report
