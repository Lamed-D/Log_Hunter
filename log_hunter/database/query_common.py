"""Shared validation errors for the read-only case query contract."""
from log_hunter.core.labels import CASE_QUERY_TEXT


class QueryInputError(ValueError):
    def __init__(self, detail):
        super().__init__(CASE_QUERY_TEXT['invalid'].format(detail=detail))
