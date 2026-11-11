"""Left tree helpers without Tk: find a node by name, the selection history (back/forward) and the selected path."""


def walk(children, item=""):
    """Item ids depth-first in display order; `children(item)` lists an item's children."""
    for child in children(item):
        yield child
        yield from walk(children, child)


def find_next(order, label, text, current=None):
    """The next item after `current` whose label contains `text` (case-insensitive), wrapping around; else None."""
    needle = text.strip().casefold()
    if not needle:
        return None
    order = list(order)
    start = order.index(current) + 1 if current in order else 0
    for item in order[start:] + order[:start]:
        if needle in (label(item) or "").casefold():
            return item
    return None


def path_text(item, parent, label, separator=" › "):
    """'찾은 기록 › 자동 실행 항목 › 예약된 작업' for an item, from the root down."""
    parts = []
    while item:
        parts.append(label(item))
        item = parent(item)
    return separator.join(reversed([p for p in parts if p]))


class History:
    """Back/forward over selected node keys (keys survive tree rebuilds, item ids do not)."""

    def __init__(self, limit=200):
        self.back_keys, self.forward_keys, self.current, self.limit = [], [], None, limit

    def visit(self, key):
        if key is None or key == self.current:
            return
        if self.current is not None:
            self.back_keys.append(self.current)
            del self.back_keys[:-self.limit]
        self.current = key
        self.forward_keys.clear()

    def back(self):
        if not self.back_keys:
            return None
        self.forward_keys.append(self.current)
        self.current = self.back_keys.pop()
        return self.current

    def forward(self):
        if not self.forward_keys:
            return None
        self.back_keys.append(self.current)
        self.current = self.forward_keys.pop()
        return self.current

    def drop(self, exists):
        """Forget keys whose node no longer exists (e.g. after re-analysis removed a category)."""
        self.back_keys = [k for k in self.back_keys if exists(k)]
        self.forward_keys = [k for k in self.forward_keys if exists(k)]
