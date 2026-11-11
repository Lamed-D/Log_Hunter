"""휴지통 기록 on screen: companion state text, when saving is possible, and the save plan (synthetic image)."""
import hashlib
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.models import ForensicEvent
from log_hunter.core.pipeline import Pipeline, apply_image_metadata
from log_hunter.image.extract import extract_artifacts
from log_hunter.image.recycle import save_recycle_pair
from log_hunter.ui import record_fields, recycle_view
from test_recycle_pair import CONTENT, pair_volume


class RecycleSaveViewTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        cls.image = root / "synthetic.img"
        cls.image.write_bytes(pair_volume())
        cls.extraction = extract_artifacts(cls.image, root / "extracted")
        cls.result = apply_image_metadata(Pipeline().analyze(cls.extraction.inputs), cls.extraction)
        cls.root = root

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def event(self, name):
        return next(e for e in self.result.events if e.details.get("i_file") == name)

    def test_state_text_and_blockers(self):
        present, folder, missing = self.event("$IFILE.txt"), self.event("$IDIR"), self.event("$IMISSING")
        self.assertEqual(recycle_view.pair_text(present.details), "짝 파일 확인")
        self.assertEqual(recycle_view.pair_text(folder.details), "짝 파일 확인 (폴더)")
        self.assertIn("짝 파일 미관측(부재 확정 아님) — 원래 디렉터리에서 일치하는 항목을 찾지 못함", recycle_view.pair_text(missing.details))
        self.assertIsNone(recycle_view.save_blocker(present))
        self.assertIn("미관측", recycle_view.save_blocker(missing))
        plain = ForensicEvent("recyclebin", "x", "파일 삭제", details={})
        self.assertIn("짝 파일 정보가 없습니다", recycle_view.save_blocker(plain))
        snap = ForensicEvent("recyclebin", "x", "파일 삭제", details={"recycle_pair": {**present.details["recycle_pair"],
                                                                                    "snapshot": {"store_id": "s"}}})
        self.assertIn("섀도 복사본", recycle_view.save_blocker(snap))
        fields = dict(record_fields.properties(present).fields)
        self.assertEqual(fields["짝 파일 여부"], "짝 파일 확인")
        self.assertTrue(fields["짝 파일 위치"].endswith("$RFILE.txt"))

    def test_plan_saves_a_new_file_and_leaves_the_image(self):
        before = hashlib.sha256(self.image.read_bytes()).hexdigest()
        event = self.event("$IFILE.txt")
        image, volume, i_path, name = recycle_view.save_plan(event, [self.extraction])
        self.assertEqual((name, volume), ("file.txt", 0))
        out = self.root / "saved"
        out.mkdir()
        saved = save_recycle_pair(image, volume, i_path, out / name, expected_pair=dict(event.details["recycle_pair"]))
        self.assertEqual((out / name).read_bytes(), CONTENT)
        self.assertTrue(Path(saved["record"]).exists())
        self.assertEqual(hashlib.sha256(self.image.read_bytes()).hexdigest(), before)
        self.assertIsNone(recycle_view.save_plan(event, []))


if __name__ == "__main__":
    unittest.main()
