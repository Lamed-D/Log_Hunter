# Teaching copy: runtime tokens are verified by tools/check_annotated.py.
"""Group USB observations without treating every interface or timestamp as a device."""
from collections import Counter, defaultdict
import re
import uuid
from log_hunter.core.labels import USB_UNKNOWN_REASON_LABELS


def _container(value):
    try:
        parsed = uuid.UUID(value)
        return str(parsed) if parsed.int else None
    except (ValueError, TypeError, AttributeError):
        return None


def _instance_key(event, index):
    d = event.details
    device, serial = d.get("device"), d.get("serial_raw", d.get("serial"))
    if device and serial:
        return event.source, d.get("bus"), device.casefold(), str(serial).casefold()
    return event.source, event.locator or ("record", index)


def usb_device_inventory(events):
    """Return conservative physical candidates and annotate representative observations.

    Identical vendor/product identifiers alone never identify a physical device.
    Groups stay inside one evidence source; no cross-host identity is inferred.
    """
    for event in events:
        if event.artifact == "usb":
            # Derived reasons must be recalculated when a different selection is grouped.
            reasons = [r for r in event.details.get("unknown_reasons", []) if r != "parent_device_unknown"]
            event.details["unknown_reasons"] = reasons
            event.details["unknown_reason_labels"] = [USB_UNKNOWN_REASON_LABELS.get(r, r) for r in reasons]
    records = [(i, e) for i, e in enumerate(events)
               if e.artifact == "usb" and e.action == "device_registration"]
    parent = list(range(len(records)))
    evidence = []
    containers = [{_container(e.details.get("containerid"))} - {None} for _, e in records]

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def join(left, right, basis, value):
        a, b = find(left), find(right)
        if a != b:
            if len(containers[a] | containers[b]) > 1:
                return
            containers[min(a, b)] |= containers[max(a, b)]
            parent[max(a, b)] = min(a, b)
            evidence.append((left, right, basis, value))

    tokens, explicit_ids, prefixes = {}, {}, defaultdict(list)
    for n, (index, event) in enumerate(records):
        d = event.details
        scope = event.source
        same = _instance_key(event, index)
        container = _container(d.get("containerid"))
        keys = [("recorded_instance", same)]
        if container:
            keys.append(("container_id", (scope, container)))
        serial = d.get("serial", "")
        match = re.search(r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", d.get("device", ""), re.I)
        if (match and isinstance(serial, str) and serial and "&" not in serial
                and not d.get("serial_may_be_generated")):
            keys.append(("vid_pid_serial", (scope, *[v.upper() for v in match.groups()], serial.casefold())))
        for basis, key in keys:
            token = basis, key
            if token in tokens:
                join(n, tokens[token], basis, key)
            else:
                tokens[token] = n
        instance_id = "\\".join(str(d.get(k, "")) for k in ("bus", "device", "serial_raw"))
        explicit_ids[(scope, instance_id.casefold())] = n
        prefix = d.get("parentidprefix")
        if isinstance(prefix, str) and prefix:
            prefixes[(scope, prefix.casefold())].append(n)

    for n, (_index, event) in enumerate(records):
        d = event.details
        recorded_parent = d.get("parent")
        target = explicit_ids.get((event.source, str(recorded_parent).casefold())) if recorded_parent else None
        logical_child = (d.get("bus") in ("HID", "USBSTOR", r"SWD\WPDBUSENUM", "BTHENUM")
                         or "&MI_" in str(d.get("device", "")).upper())
        if target is not None and logical_child:
            target_details = records[target][1].details
            if (target_details.get("device_kind") != "hub" and
                    not str(target_details.get("device", "")).upper().startswith("ROOT_HUB")):
                join(n, target, "recorded_parent", recorded_parent)
        # Generated child instances are matched only to one recorded parent prefix.
        serial = str(d.get("serial_raw", "")).casefold()
        if d.get("bus") in ("USB", "HID") and "&" in serial:
            prefix = serial.rsplit("&", 1)[0]
            candidates = prefixes.get((event.source, prefix), [])
            if len(candidates) == 1 and candidates[0] != n:
                candidate = records[candidates[0]][1].details
                if (candidate.get("device_kind") != "hub" and
                        not str(candidate.get("device", "")).upper().startswith("ROOT_HUB")):
                    join(n, candidates[0], "unique_parent_prefix", prefix)

    members = defaultdict(list)
    for n, (index, event) in enumerate(records):
        members[find(n)].append((n, index, event))
    observations = defaultdict(list)
    for index, event in enumerate(events):
        if event.artifact == "usb":
            observations[_instance_key(event, index)].append(index)
    groups = []
    edges = defaultdict(list)
    for left, right, basis, value in evidence:
        edges[find(left)].append({"left": records[left][0], "right": records[right][0],
                                  "basis": basis, "value": value})
    for ordinal, (root, group) in enumerate(members.items()):
        registration_indices = [index for _, index, _ in group]
        keys = {_instance_key(event, original) for _, original, event in group}
        event_indices = sorted({index for key in keys for index in observations[key]})
        kinds = sorted({e.details.get("device_kind", "unknown") for _, _, e in group})
        system = all(e.details.get("device_kind") == "hub" or
                     str(e.details.get("device", "")).upper().startswith("ROOT_HUB") for _, _, e in group)
        auxiliary = all(e.details.get("physical_observation") is False or
                        (e.details.get("bus") == "BTHENUM" and
                         str(e.details.get("device", "")).startswith("{")) for _, _, e in group)
        orphan_hid = all(e.details.get("bus") == "HID" for _, _, e in group)
        reasons = sorted({r for _, _, e in group for r in e.details.get("unknown_reasons", [])}
                         | ({"parent_device_unknown"} if orphan_hid else set()))
        names = [e.details.get("friendlyname") or e.details.get("friendly_name") or e.details.get("devicedesc")
                 for _, _, e in group]
        names = [name for name in names if isinstance(name, str) and name]
        result = {"group_id": "usb:" + str(ordinal), "registration_indices": registration_indices,
                  "event_indices": event_indices, "device_kinds": kinds,
                  "display_name": names[0] if names else None, "system_device": system,
                  "auxiliary_device": auxiliary, "default_visible": not system and not auxiliary,
                  "grouping_evidence": edges[root], "sources": sorted({e.source for _, _, e in group}),
                  "physical_identity_confirmed": False, "unknown_reasons": reasons,
                  "unknown_reason_labels": [USB_UNKNOWN_REASON_LABELS.get(r, r) for r in reasons]}
        groups.append(result)
        bases = sorted({edge["basis"] for edge in edges[root]}) or ["single_observation"]
        for index in event_indices:
            events[index].details.update(physical_device_id=result["group_id"],
                physical_group_basis=bases, physical_device_representative=index == registration_indices[0] and not auxiliary,
                device_inventory_visible=result["default_visible"], system_device=system,
                auxiliary_device=auxiliary, physical_identity_confirmed=False)
            if orphan_hid and "parent_device_unknown" not in events[index].details["unknown_reasons"]:
                events[index].details["unknown_reasons"].append("parent_device_unknown")
                events[index].details["unknown_reason_labels"].append(USB_UNKNOWN_REASON_LABELS["parent_device_unknown"])
    counts = Counter({"registration_records": len(records), "physical_groups": sum(not g["auxiliary_device"] for g in groups),
                      "default_visible_groups": sum(g["default_visible"] for g in groups),
                      "system_groups": sum(g["system_device"] for g in groups),
                      "auxiliary_groups": sum(g["auxiliary_device"] for g in groups),
                      "unknown_groups": sum(g["device_kinds"] == ["unknown"] and g["default_visible"] for g in groups)})
    return {"groups": groups, "counts": dict(counts)}
