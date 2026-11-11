"""Saved Wi-Fi profiles on screen and in the report (synthetic profile values only)."""
import tempfile
import unittest
from pathlib import Path

from log_hunter.core import wifi_view
from log_hunter.core.models import ForensicEvent
from log_hunter.core.pipeline import AnalysisResult
from log_hunter.core.tree import TreeNode
from log_hunter.main import save_result
from log_hunter.ui import columns, record_fields


def profile(**details):
    base = {"profile_name": "TestNetwork", "ssid_name": " TestNetwork ", "authentication": "WPA2PSK", "encryption": "AES",
            "automatic_connection": False, "password_stored_in_profile": True, "password_protected": True,
            "wifi_password": "<b>fake-key</b>", "password_state": "decrypted", "password_source": "dpapi_input_blob",
            "networklist_candidates": [{"date_last_connected_local": "2024-01-01T09:00:00", "timezone_known": False,
                                        "identity_confirmed": False}, {}],
            "networklist_link_ambiguous": True}
    return ForensicEvent("wlan", r"C:\Evidence\Wlansvc\Profiles\Interfaces\{x}\1.xml", "wlan_profile",
                         details={**base, **details})


class WifiViewTest(unittest.TestCase):
    def test_cells(self):
        event = profile()
        shown = {key: wifi_view.cell(key, event) for key in wifi_view.COLUMNS}
        self.assertEqual(shown["ssid_name"], "“ TestNetwork ”")  # edge spaces kept and visible
        self.assertEqual(shown["automatic_connection"], "수동 연결 설정")  # False is meaningful
        self.assertEqual(shown["wifi_password"], "<b>fake-key</b>")
        self.assertEqual(shown["password_state"], "공유키 복호화 성공 (접속 성공 확인 아님)")
        self.assertEqual(shown["password_source"], "입력한 보호 키를 복호화")
        self.assertIn("후보 2개 (같은 프로필로 확정 아님)", shown["networklist"])
        self.assertIn("(시간대 미상)", shown["networklist"])
        self.assertIn("후보 여러 개", shown["networklist"])
        live = profile(password_state="verified_live_candidate")
        self.assertTrue(wifi_view.cell("wifi_password", live).endswith("(현재 프로필 후보)"))
        none = profile(wifi_password=None, password_state="context_unavailable", automatic_connection=None)
        self.assertEqual(wifi_view.cell("wifi_password", none), "")
        self.assertIn("복호화 불가", wifi_view.cell("password_state", none))
        self.assertEqual(wifi_view.cell("automatic_connection", none), "")
        other = ForensicEvent("network", r"C:\Evidence\SOFTWARE", "network_profile", details={"ssid_name": "x"})
        self.assertEqual(wifi_view.cell("ssid_name", other), "")

    def test_table_and_properties(self):
        node = TreeNode("art:network", "네트워크·Wi-Fi", "artifacts", ("network", "wlan"))
        cols = columns.columns_for(node)
        self.assertIn("wifi_password", [c.key for c in cols])
        shown = dict(zip([c.key for c in cols], columns.row(profile(), cols, {}, None)))
        self.assertEqual(shown["password_state"], "공유키 복호화 성공 (접속 성공 확인 아님)")
        props = record_fields.properties(profile())
        fields = dict(props.fields)
        self.assertEqual(fields["프로필 이름"], "TestNetwork")
        self.assertEqual(fields["공유키"], "<b>fake-key</b>")
        self.assertEqual(fields["원문 공유키 보호"], "예")

    def test_report_tab_is_escaped_and_only_when_profiles_exist(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "out"
            save_result(AnalysisResult(events=[profile()]), out)
            page = (out / "report.html").read_text(encoding="utf-8")
            self.assertIn('data-panel="wifi">Wi-Fi 프로필', page)
            self.assertIn("&lt;b&gt;fake-key&lt;/b&gt;", page)
            self.assertNotIn("<td><b>fake-key</b>", page)
            plain = Path(temp) / "plain"
            save_result(AnalysisResult(events=[]), plain)
            self.assertNotIn('data-panel="wifi"', (plain / "report.html").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
