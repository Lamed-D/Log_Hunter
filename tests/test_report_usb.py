"""Report USB tab: result-table columns, tree grouping, hidden entries not counted as devices (synthetic values)."""
import re
import tempfile
import unittest
from pathlib import Path

from log_hunter.core.models import ForensicEvent
from log_hunter.core.pipeline import AnalysisResult
from log_hunter.main import save_result

SRC = r"C:\Evidence\SYSTEM"


def usb(kind, group, name, **details):
    return ForensicEvent("usb", SRC, "device_registration", timestamp="2024-01-01T00:00:00+00:00",
                         time_field="key_lastwrite",
                         details={"device_kind": kind, "physical_device_id": group, "friendlyname": name,
                                  "physical_group_basis": ["single_observation"], **details})


def events():
    return [
        usb("keyboard", "usb:1", "TEST keyboard", physical_group_basis=["container_id"]),
        usb("mouse", "usb:1", "TEST mouse", physical_group_basis=["container_id"]),
        usb("unknown", "usb:2", None, unknown_reason_labels=["장치 이름·설명 기록 없음"]),
        usb("hub", "usb:3", "TEST hub", system_device=True, device_inventory_visible=False),
        usb("portable", "usb:4", "<b>TEST volume</b>", auxiliary_device=True, physical_observation=False,
            device_inventory_visible=False, unknown_reason_labels=["장치 이름만 남은 메타데이터 관측(별도 물리 장치 아님)"]),
    ]


class ReportUsbTest(unittest.TestCase):
    def page(self, evs):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "out"
            save_result(AnalysisResult(events=evs), out)
            return (out / "report.html").read_text(encoding="utf-8")

    def test_usb_tab_groups_and_counts(self):
        page = self.page(events())
        self.assertIn('data-panel="usb">USB·외부 장치', page)
        panel = page[page.index('<div class="panel" id="usb">'):]
        panel = panel[:panel.index("</table>")]
        self.assertIn("물리 장치 후보 2개 (기록 3건) · 시스템 장치 기록 1건 · 보조 항목 기록 1건", panel)
        for head in ("구분", "물리 장치 묶음", "알 수 없는 이유", "장치 종류"):
            self.assertIn(f"<th>{head}</th>", panel)
        rows = re.findall(r"<tr><td>(.*?)</td>", panel)
        self.assertEqual(rows, ["물리 장치 후보"] * 3 + ["시스템 장치 (허브·컨트롤러)", "보조 항목 (별도 물리 장치 아님)"])
        self.assertIn("장치 이름·설명 기록 없음", panel)
        self.assertIn("usb:4 · 보조 항목(별도 물리 장치 아님)", panel)
        self.assertIn("&lt;b&gt;TEST volume&lt;/b&gt;", panel)
        self.assertNotIn("<b>TEST volume</b>", panel)

    def test_group_records_stay_together(self):
        evs = [usb("mouse", "usb:1", "TEST mouse"), usb("keyboard", "usb:1", "TEST keyboard", physical_device_representative=True),
               usb("keyboard", "usb:0", "TEST other keyboard")]
        page = self.page(evs)
        panel = page[page.index('<div class="panel" id="usb">'):]
        names = re.findall(r"(TEST (?:other keyboard|keyboard|mouse))</td>", panel[:panel.index("</table>")])
        self.assertEqual(names, ["TEST other keyboard", "TEST keyboard", "TEST mouse"])

    def test_no_usb_no_tab(self):
        self.assertNotIn('data-panel="usb"', self.page([ForensicEvent("run", SRC, "autorun", details={})]))


if __name__ == "__main__":
    unittest.main()
