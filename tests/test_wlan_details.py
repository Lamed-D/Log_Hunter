"""합성 WLAN 프로필과 가짜 공유키로 정보·복호화·출처 일치를 검사합니다."""
import ctypes
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
from xml.sax.saxutils import escape

from log_hunter.parser.wlan import parse_wlan_xml,WLANParser
from log_hunter.parser.wlan_keys import unprotect_key,verified_profile_candidate,_Blob
from log_hunter.core.wlan_profiles import link_wlan_profiles
from log_hunter.core.models import ForensicEvent

KEY='0102030405060708090A0B0C0D0E0F10'
GUID='{00000000-0000-0000-0000-000000000001}'
PASSWORD=' TestPassword0001 '


def profile(protected='true',key=KEY,ssid='TestNetwork',mode='manual'):
    return ('<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">'
        '<name>TestNetwork</name><SSIDConfig><SSID><name>'+escape(ssid)+'</name></SSID></SSIDConfig>'
        '<connectionType>ESS</connectionType><connectionMode>'+mode+'</connectionMode><MSM><security>'
        '<authEncryption><authentication>WPA3SAE</authentication><encryption>GCMP256</encryption></authEncryption>'
        '<sharedKey><protected>'+protected+'</protected><keyMaterial>'+escape(key)+'</keyMaterial></sharedKey>'
        '</security></MSM></WLANProfile>')


class WLANDetailsTests(unittest.TestCase):
    def test_metadata_plaintext_spaces_and_manual_mode(self):
        result=parse_wlan_xml(profile('false',PASSWORD,ssid=' TestNetwork '))
        self.assertEqual(result['ssid_name'],' TestNetwork ')
        self.assertEqual(result['wifi_password'],PASSWORD)
        self.assertTrue(result['password_stored_in_profile'])
        self.assertFalse(result['password_protected'])
        self.assertFalse(result['automatic_connection'])
        self.assertEqual(result['authentication'],'WPA3SAE')
        self.assertEqual(result['encryption'],'GCMP256')
        self.assertEqual(result['password_state'],'plaintext_in_profile')
        with patch('log_hunter.parser.wlan_keys.unprotect_key',return_value=(PASSWORD+'\0').encode('utf-16-le')) as decrypt:
            result=parse_wlan_xml(profile(),decrypt=True)
        self.assertEqual(result['wifi_password'],PASSWORD)
        self.assertEqual(result['password_source'],'dpapi_input_blob')
        self.assertFalse(result['cleartext_password_found'])
        decrypt.assert_called_once_with(bytes.fromhex(KEY))

    def test_failed_decryption_never_leaks_ciphertext_or_queries_other_profiles(self):
        with patch('log_hunter.parser.wlan_keys.unprotect_key',side_effect=OSError(13,KEY)), \
                patch('log_hunter.parser.wlan_keys.verified_profile_candidate') as lookup:
            result=parse_wlan_xml(profile(),source_path='C:/Evidence/profile.xml',decrypt=True)
        self.assertIsNone(result['wifi_password'])
        self.assertEqual(result['password_state'],'context_unavailable')
        self.assertNotIn(KEY,json.dumps(result))
        self.assertNotIn('keyMaterial',result)
        lookup.assert_not_called()
        with patch('log_hunter.parser.wlan_keys.unprotect_key',side_effect=NotImplementedError):
            result=parse_wlan_xml(profile(),decrypt=True)
        self.assertEqual(result['password_state'],'platform_unavailable')
        result=parse_wlan_xml(profile(key='not hex'),decrypt=True)
        self.assertEqual(result['password_state'],'invalid_or_unsupported_key')

    def test_live_candidate_checks_blob_and_ssid_before_and_after(self):
        encrypted=profile();plain=profile('false',PASSWORD)
        with patch('log_hunter.parser.wlan_keys._profile_xml',side_effect=[encrypted,plain,encrypted]) as lookup:
            self.assertEqual(verified_profile_candidate(bytes.fromhex(KEY),GUID,'TestNetwork','TestNetwork'),PASSWORD)
        self.assertEqual(lookup.call_count,3)
        for before in (profile(key='11'),profile(ssid='Example-WiFi')):
            with patch('log_hunter.parser.wlan_keys._profile_xml',return_value=before) as lookup:
                self.assertIsNone(verified_profile_candidate(bytes.fromhex(KEY),GUID,'TestNetwork','TestNetwork'))
                self.assertEqual(lookup.call_count,1)
        with patch('log_hunter.parser.wlan_keys._profile_xml',side_effect=[encrypted,plain,profile(key='22')]):
            self.assertIsNone(verified_profile_candidate(bytes.fromhex(KEY),GUID,'TestNetwork','TestNetwork'))

    def test_parser_marks_verified_live_value_as_candidate(self):
        with patch('log_hunter.parser.wlan_keys.unprotect_key',side_effect=OSError(13,'문맥 없음')), \
                patch('log_hunter.parser.wlan_keys.verified_profile_candidate',return_value=PASSWORD):
            result=parse_wlan_xml(profile(),source_path='C:/Evidence/Interfaces/'+GUID+'/profile.xml',decrypt=True)
        self.assertEqual(result['wifi_password'],PASSWORD)
        self.assertEqual(result['password_state'],'verified_live_candidate')
        self.assertEqual(result['password_source'],'protected_blob_checked_before_after')
        self.assertIsNone(result['password_decryption_error'])

    def test_utf16_xml_damage_limits_and_later_profile_continue(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)
            (p/'a.xml').write_bytes(b'<!DOCTYPE a [<!ENTITY b "x">]><WLANProfile>&b;</WLANProfile>')
            valid=profile('false',PASSWORD).replace('<WLANProfile','<?xml version="1.0" encoding="utf-16"?><WLANProfile',1)
            (p/'b.xml').write_bytes(valid.encode('utf-16'))
            parser=WLANParser();events=list(parser.parse(p))
        self.assertEqual(len(events),1)
        self.assertEqual(events[0].details['wifi_password'],PASSWORD)
        self.assertFalse(events[0].details['automatic_connection'])
        self.assertTrue(parser.errors)
        self.assertIsNone(parse_wlan_xml('x'*(1024*1024+1)))
        self.assertIsNone(parse_wlan_xml(profile().replace('</WLANProfile>','')))

    def test_networklist_times_are_local_candidates_not_profile_creation_facts(self):
        wifi=ForensicEvent('wlan','generated','wlan_profile',details={'ssid_name':'TestNetwork'})
        network=ForensicEvent('network','generated','network_profile',details={'profile_name':'TestNetwork',
            'name_type':71,'date_created':'2024-01-01T10:00:00','date_last_connected':'2024-01-02T10:00:00'})
        link_wlan_profiles([wifi,network])
        candidate=wifi.details['networklist_candidates'][0]
        self.assertFalse(candidate['identity_confirmed'])
        self.assertFalse(candidate['timezone_known'])
        self.assertEqual(candidate['date_created_local'],'2024-01-01T10:00:00')
        self.assertIsNone(wifi.timestamp)
        link_wlan_profiles([wifi,network,network])
        self.assertTrue(wifi.details['networklist_link_ambiguous'])
        wrong_case=ForensicEvent('wlan','generated','wlan_profile',details={'ssid_name':'testnetwork'})
        link_wlan_profiles([wrong_case,network])
        self.assertNotIn('networklist_candidates',wrong_case.details)

    def test_pipeline_links_generated_networklist_and_exports_requested_password(self):
        from test_example_samples import load_demo
        from log_hunter.core.pipeline import Pipeline
        from log_hunter.main import save_result
        b=load_demo().HiveBuilder();stamp=133485408000000000
        key=b.key(GUID,stamp,values=[('ProfileName',1,'TestNetwork\0'.encode('utf-16-le')),
            ('NameType',4,struct.pack('<I',71)),('DateCreated',3,struct.pack('<8H',2024,1,1,1,10,0,0,0)),
            ('DateLastConnected',3,struct.pack('<8H',2024,1,2,2,10,0,0,0))])
        for name in ('Profiles','NetworkList','CurrentVersion','Windows NT','Microsoft'):
            key=b.key(name,stamp,children=[key])
        root=b.key('ROOT',stamp,children=[key])
        secret='TEST</script><script>alert(1)</script>'
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder);xml=p/'profile.xml';hive=p/'SOFTWARE'
            xml.write_text(profile('false',secret),encoding='utf-8');before=xml.read_bytes()
            hive.write_bytes(b.build(root))
            result=Pipeline().analyze([('wlan',xml),('network',hive)])
            event=next(e for e in result.events if e.artifact=='wlan')
            self.assertEqual(event.details['networklist_candidates'][0]['date_created_local'],'2024-01-01T10:00:00.000')
            self.assertEqual(event.details['wifi_password'],secret)
            save_result(result,p/'case')
            report=json.loads((p/'case'/'report.json').read_text(encoding='utf-8'))
            self.assertEqual(next(e for e in report['events'] if e['artifact']=='wlan')['details']['wifi_password'],secret)
            self.assertNotIn('<script>alert(1)</script>',(p/'case'/'report.html').read_text(encoding='utf-8'))
            self.assertEqual(xml.read_bytes(),before)

    @unittest.skipUnless(os.name=='nt','Windows DPAPI 합성 왕복 검사')
    def test_native_dpapi_roundtrip_uses_only_generated_plaintext(self):
        from ctypes import wintypes
        api=ctypes.WinDLL('crypt32',use_last_error=True)
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        api.CryptProtectData.argtypes=[ctypes.POINTER(_Blob),wintypes.LPCWSTR,ctypes.c_void_p,
            ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(_Blob)]
        api.CryptProtectData.restype=wintypes.BOOL
        kernel.LocalFree.argtypes=[ctypes.c_void_p];kernel.LocalFree.restype=ctypes.c_void_p
        raw=(PASSWORD+'\0').encode('utf-16-le');buffer=(ctypes.c_ubyte*len(raw)).from_buffer_copy(raw)
        source=_Blob(len(raw),buffer);encrypted=_Blob()
        self.assertTrue(api.CryptProtectData(ctypes.byref(source),None,None,None,None,1,ctypes.byref(encrypted)))
        try:
            cipher=ctypes.string_at(encrypted.pbData,encrypted.cbData)
            self.assertEqual(unprotect_key(cipher),raw)
            result=parse_wlan_xml(profile(key=cipher.hex()),decrypt=True)
            self.assertEqual(result['wifi_password'],PASSWORD)
            self.assertEqual(result['password_state'],'decrypted')
        finally:
            kernel.LocalFree(encrypted.pbData)
            ctypes.memset(buffer,0,len(raw))
