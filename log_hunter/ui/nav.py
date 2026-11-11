"""Left navigation tree widget filling; the tree model itself is core.tree (no Tk)."""


from log_hunter.core.sid_resolver import is_service_sid
from .fs_model import needs_loading

PLACEHOLDER = "펼치면 읽습니다"


def fill_nav(nav, roots, parent="", depth=0):
    """Insert TreeNode roots into a Treeview. Roots and the data source's first level start open;
    file system folders not read yet get a placeholder child so they show an expand arrow.
    Returns {item id: TreeNode}."""
    nodes = {}

    def insert(parent, node, depth):
        tags = ("service_account",) if node.kind == "account" and is_service_sid(node.value) else ()
        iid = nav.insert(parent, "end", text=node.text, tags=tags,
                         open=depth == 0 or (depth == 1 and node.key.startswith("src:")))
        nodes[iid] = node
        if needs_loading(node):
            nav.insert(iid, "end", text=PLACEHOLDER)
        for child in node.children:
            insert(iid, child, depth + 1)

    for node in roots:
        insert(parent, node, depth)
    return nodes


def node_action(node):
    """What selecting a node does: None (nothing), ("relations", type), ("errors", severity) or ("events", node)."""
    if node is None or node.kind == "group":
        return None
    if node.kind == "relation":
        return "relations", node.value
    if node.kind == "errors":
        return "errors", node.value
    if node.kind == "fileview":
        return "fileview", node.value
    if node.kind == "snapshot":
        return "snapshot", node.value
    if node.kind == "tagged_files":
        return "tagged_files", node
    return "events", node
