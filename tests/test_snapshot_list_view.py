"""Existing shadow copy list in the data source tree: a list only, never presented as readable."""
import tempfile
import unittest
from pathlib import Path

from log_hunter.image.vss import list_snapshots
from log_hunter.ui import fs_model, nav
from test_vss_catalog import catalog


class SnapshotListViewTest(unittest.TestCase):
    def setUp(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "synthetic.raw"
            path.write_bytes(catalog())
            self.catalogs = list_snapshots(path)

    def test_nodes_and_info(self):
        nodes = fs_model.snapshot_nodes("synthetic.raw", "synthetic.raw", self.catalogs)
        self.assertEqual([n.label for n in nodes], ["볼륨 0 섀도 복사본 (2개)"])
        first = nodes[0].children[0]
        self.assertEqual(first.label, "2020-12-30T00:00:01+00:00 · 스토어 00000000-0000-0000-0000-000000000001")
        self.assertEqual(nav.node_action(first)[0], "snapshot")
        self.assertIsNone(nav.node_action(nodes[0]))  # the group itself does nothing
        info = dict(fs_model.snapshot_info(first.value))
        self.assertEqual(info["스냅숏 생성 시각"], "2020-12-30T00:00:01+00:00")
        self.assertIn("파일 생성·실행 시각이 아닙니다", info["시각의 의미"])
        self.assertEqual(info["내용 읽기"], "아직 지원 안 함 (목록만)")
        self.assertIn("GUID로 단정하지 않습니다", info["스토어 식별자 설명"])

    def test_flags_errors_and_absent(self):
        catalog_ = dict(self.catalogs[0])
        catalog_["snapshots"] = [{**catalog_["snapshots"][0], "ambiguous": True, "catalog_complete": False, "created_at": None}]
        catalog_["errors"] = [{"locator": "catalog:16384", "message": "손상된 카탈로그 블록"}]
        group = fs_model.snapshot_nodes("x", "x", [catalog_])[0]
        self.assertEqual(group.children[0].label, "생성 시각 알 수 없음 · 스토어 00000000-0000-0000-0000-000000000001 (목록 항목이 모호함, 목록 불완전)")
        errors = group.children[1]
        self.assertEqual(errors.label, "목록 진단: 문제 1건")
        self.assertIn(("진단", "catalog:16384: 손상된 카탈로그 블록"), fs_model.snapshot_info(errors.value))
        absent = {**catalog_, "present": False, "errors": [], "snapshots": []}
        self.assertEqual(fs_model.snapshot_nodes("x", "x", [absent]), [])
        failed = fs_model.snapshot_nodes("x", "x", {"error": "읽기 실패"})
        self.assertEqual(failed[0].label, "섀도 복사본 목록을 읽지 못했습니다: 읽기 실패")
        self.assertEqual(fs_model.snapshot_nodes("x", "x", None), [])


if __name__ == "__main__":
    unittest.main()
