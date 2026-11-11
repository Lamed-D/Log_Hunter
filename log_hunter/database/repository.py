import json
import sqlite3
from dataclasses import asdict


ENTITY_TABLES = ("users", "processes", "files", "urls", "devices")


def _dedup_key(table, value):
    if not value:
        return None
    text = str(value).strip()
    if table == "urls":
        text = text.rstrip("/")
    if table == "users":
        text = text.upper()
    else:
        text = text.casefold()
    return text


class Repository:
    def __init__(self, path):
        self.connection = sqlite3.connect(path)
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.executescript('''
            CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY, name TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS evidence_files(id INTEGER PRIMARY KEY, case_id INTEGER REFERENCES cases(id), data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, case_id INTEGER REFERENCES cases(id), artifact TEXT, timestamp TEXT, sid TEXT, data TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS events_timeline ON events(case_id,timestamp);
            CREATE TABLE IF NOT EXISTS parser_errors(id INTEGER PRIMARY KEY, case_id INTEGER REFERENCES cases(id), data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS relations(id INTEGER PRIMARY KEY, case_id INTEGER REFERENCES cases(id), left_event INTEGER REFERENCES events(id), right_event INTEGER REFERENCES events(id), data TEXT NOT NULL);
        ''')
        for name in ENTITY_TABLES:
            self.connection.execute(f"CREATE TABLE IF NOT EXISTS {name}(id INTEGER PRIMARY KEY, case_id INTEGER REFERENCES cases(id), data TEXT NOT NULL)")
        self.connection.executescript('''
            CREATE TABLE IF NOT EXISTS entity_events(
                id INTEGER PRIMARY KEY,
                entity_type TEXT NOT NULL,
                entity_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS entity_events_unique ON entity_events(entity_type, entity_id, event_id);
            CREATE INDEX IF NOT EXISTS entity_events_by_event ON entity_events(event_id);
        ''')

    def save(self, name, evidence, events, errors, relations, *, state=None, tags=()):
        def encode(value):
            return json.dumps(value, ensure_ascii=False, sort_keys=True)

        with self.connection:
            case = self.connection.execute("INSERT INTO cases(name) VALUES(?)", (name,)).lastrowid
            for item in evidence:
                self.connection.execute("INSERT INTO evidence_files(case_id,data) VALUES(?,?)", (case, encode(asdict(item))))

            seen_entities = {}
            ids = []
            for event in events:
                event_row_id = self.connection.execute(
                    "INSERT INTO events(case_id,artifact,timestamp,sid,data) VALUES(?,?,?,?,?)",
                    (case, event.artifact, event.timestamp, event.sid, encode(event.to_dict()))
                ).lastrowid
                ids.append(event_row_id)

                for table, value in (("users", event.sid), ("processes", event.process),
                                     ("files", event.path), ("urls", event.url),
                                     ("devices", event.details.get("device"))):
                    if not value:
                        continue
                    key = _dedup_key(table, value)
                    if key is None:
                        continue
                    lookup = (table, key)
                    if lookup in seen_entities:
                        entity_id, entity_data = seen_entities[lookup]
                        entity_data["event_ids"].append(event_row_id)
                        entity_data["count"] = len(entity_data["event_ids"])
                    else:
                        entity_data = {"value": value, "normalized": key, "event_ids": [event_row_id], "count": 1}
                        entity_id = self.connection.execute(
                            f"INSERT INTO {table}(case_id,data) VALUES(?,?)",
                            (case, "{}")
                        ).lastrowid
                        seen_entities[lookup] = (entity_id, entity_data)

                    self.connection.execute(
                        "INSERT OR IGNORE INTO entity_events(entity_type,entity_id,event_id) VALUES(?,?,?)",
                        (table, entity_id, event_row_id)
                    )

            # Serialize each accumulated entity list once, inside the same transaction.
            for (table, key), (entity_id, entity_data) in seen_entities.items():
                self.connection.execute(
                    f"UPDATE {table} SET data=? WHERE id=?", (encode(entity_data), entity_id))

            for error in errors:
                self.connection.execute("INSERT INTO parser_errors(case_id,data) VALUES(?,?)", (case, encode(asdict(error))))
            for relation in relations:
                # Group relations (execution_chain, program_group) list event_indices instead of a left/right pair.
                left, right = relation.get("left"), relation.get("right")
                self.connection.execute("INSERT INTO relations(case_id,left_event,right_event,data) VALUES(?,?,?,?)",
                                        (case, _row(ids, left), _row(ids, right), encode(relation)))
            if state is not None:
                self.connection.execute("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                self.connection.execute("CREATE TABLE IF NOT EXISTS case_state(case_id INTEGER PRIMARY KEY REFERENCES cases(id), data TEXT NOT NULL)")
                self.connection.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version','1')")
                self.connection.execute("INSERT INTO case_state(case_id,data) VALUES(?,?)", (case, encode(state)))
                self.connection.executemany("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
                                            ((k, str(state[k])) for k in ('tool_version', 'created_at')))
            if tags:
                self.connection.execute("CREATE TABLE IF NOT EXISTS examiner_tags(id INTEGER PRIMARY KEY, key TEXT NOT NULL, data TEXT NOT NULL)")
                self.connection.executemany("INSERT INTO examiner_tags(key,data) VALUES(?,?)",
                                            ((r['key'], encode(r)) for r in tags))
            if state is not None:
                from .query_index import build_case_index
                build_case_index(self.connection, case, state, relations)
        return case

    def query_entity(self, case_id, table, value):
        if table not in ENTITY_TABLES:
            raise ValueError(f"유효하지 않은 엔티티 테이블: {table}")
        key = _dedup_key(table, value)
        if key is None:
            return []
        rows = self.connection.execute(
            f"SELECT data FROM {table} WHERE case_id=?", (case_id,)
        ).fetchall()
        for (data_json,) in rows:
            data = json.loads(data_json)
            if data.get("normalized") == key:
                event_ids = data.get("event_ids", [data.get("event_id")])
                if not event_ids:
                    return []
                placeholders = ",".join("?" * len(event_ids))
                events = self.connection.execute(
                    f"SELECT data FROM events WHERE id IN ({placeholders})", event_ids
                ).fetchall()
                return [json.loads(row[0]) for row in events]
        return []

    def entity_summary(self, case_id):
        summary = {}
        for table in ENTITY_TABLES:
            rows = self.connection.execute(
                f"SELECT data FROM {table} WHERE case_id=?", (case_id,)
            ).fetchall()
            entities = []
            for (data_json,) in rows:
                data = json.loads(data_json)
                entities.append({"value": data.get("value", ""), "count": data.get("count", 1)})
            entities.sort(key=lambda e: e["count"], reverse=True)
            summary[table] = {"total": len(entities), "top": entities[:10]}
        return summary

    def close(self):
        self.connection.close()


def _row(ids, index):
    return ids[index] if isinstance(index, int) and 0 <= index < len(ids) else None
