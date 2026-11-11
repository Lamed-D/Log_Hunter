# ▶ DB 조회: 원본 증거를 열지 않고 저장된 기록을 필요한 범위만 읽습니다.
"""Shared validation errors for the read-only case query contract."""
from log_hunter.core.labels import CASE_QUERY_TEXT


class QueryInputError(ValueError):
    def __init__(self, detail):
        super().__init__(CASE_QUERY_TEXT['invalid'].format(detail=detail))
