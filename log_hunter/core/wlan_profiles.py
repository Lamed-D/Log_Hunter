"""Wi-Fi와 NetworkList를 이름 일치 후보로만 연결하며 시각 의미를 보존합니다."""
from collections import defaultdict


def link_wlan_profiles(events):
    networks=defaultdict(list)
    for event in events:
        details=event.details or {}
        if event.artifact=='network' and event.action=='network_profile' and details.get('name_type')==71:
            name=details.get('profile_name')
            if isinstance(name,str) and name:
                networks[name].append(event)
    for event in events:
        if event.artifact!='wlan':
            continue
        name=event.details.get('ssid_name')
        matches=networks.get(name,[]) if isinstance(name,str) else []
        if not matches:
            continue
        event.details['networklist_candidates']=[{
            'profile_guid':match.details.get('profile_guid'),
            'profile_name':match.details.get('profile_name'),
            'date_created_local':match.details.get('date_created'),
            'date_last_connected_local':match.details.get('date_last_connected'),
            'timezone_known':match.details.get('timezone_known',False),
            'identity_confirmed':False,
            'basis':'exact_ssid_profile_name_candidate',
            'source':match.source,'locator':match.locator,
        } for match in matches[:16]]
        event.details['networklist_link_ambiguous']=len(matches)>1
        event.details['networklist_candidates_truncated']=len(matches)>16
    return events
