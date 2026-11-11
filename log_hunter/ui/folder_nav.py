"""Moving between folders in the file list: back/forward history and the clickable path (no Tk)."""


def folder_key(fs):
    """Identity of a folder across tree rebuilds: (image, volume, path parts)."""
    return fs["image"], fs["volume"], tuple(fs["parts"])


def parent_key(key):
    image, volume, parts = key
    return (image, volume, parts[:-1]) if parts else None


def crumbs(key, source_name):
    """[(label, key)] from the volume root down to the folder, for the path bar."""
    image, volume, parts = key
    items = [(f"{source_name} 볼륨 {volume}", (image, volume, ()))]
    for depth, name in enumerate(parts, 1):
        items.append((name, (image, volume, tuple(parts[:depth]))))
    return items


class FolderHistory:
    """Back/forward like a file explorer. Visiting a new folder drops the forward list."""

    def __init__(self, limit=200):
        self.items, self.index, self.limit = [], -1, limit

    def visit(self, key):
        if 0 <= self.index < len(self.items) and self.items[self.index] == key:
            return
        del self.items[self.index + 1:]
        self.items.append(key)
        if len(self.items) > self.limit:
            del self.items[0]
        self.index = len(self.items) - 1

    def can_back(self):
        return self.index > 0

    def can_forward(self):
        return self.index < len(self.items) - 1

    def back(self):
        if not self.can_back():
            return None
        self.index -= 1
        return self.items[self.index]

    def forward(self):
        if not self.can_forward():
            return None
        self.index += 1
        return self.items[self.index]
