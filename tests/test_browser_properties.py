"""Properties dialog of browser and e-mail records shows their own fields, not only the generic ones."""
import unittest

from log_hunter.core.models import ForensicEvent
from log_hunter.ui.record_fields import properties

T = "2024-01-01T00:00:00+00:00"


class BrowserPropertyTests(unittest.TestCase):
    def fields(self, event):
        return dict(properties(event).fields)

    def test_cookie_fields(self):
        cookie = ForensicEvent("cookies", "Cookies", "cookie_stored", T, "cookie_last_access", url=".example.com",
                               details={"cookie_site": ".example.com", "cookie_name": "session", "cookie_path": "/",
                                        "cookie_created": T, "browser": "Microsoft Edge"})
        fields = self.fields(cookie)
        self.assertEqual(fields["쿠키 이름"], "session")
        self.assertEqual(fields["만든 시각"], "2024-01-01 00:00:00 UTC")
        self.assertEqual(fields["만료 시각"], "알 수 없음")
        self.assertEqual(fields["시각의 의미"], "쿠키 마지막 사용")

    def test_email_and_extension_and_search(self):
        mail = ForensicEvent("email", "a.eml", "email_message", T, "email_sent",
                             details={"email_subject": "제목", "email_from": ["alice@example.com"],
                                      "email_to": ["bob@example.org", "carol@example.org"], "email_attachments": []})
        fields = self.fields(mail)
        self.assertEqual(fields["보낸 사람"], "alice@example.com")
        self.assertEqual(fields["받는 사람"], "bob@example.org, carol@example.org")
        self.assertEqual(fields["첨부 이름"], "알 수 없음")
        ext = ForensicEvent("browser_extensions", "Secure Preferences", "extension_installed", T, "extension_installed",
                            details={"extension_name": "Tool", "extension_id": "abc", "extension_enabled": False,
                                     "extension_permissions": ["tabs"]})
        self.assertEqual((self.fields(ext)["켜짐"], self.fields(ext)["권한"]), ("아니요", "tabs"))
        search = ForensicEvent("history", "History", "web_search", T, "search_last_visit", url="https://example.com/?q=a",
                               details={"search_term": "a"})
        self.assertEqual(self.fields(search)["검색어"], "a")


if __name__ == "__main__":
    unittest.main()
