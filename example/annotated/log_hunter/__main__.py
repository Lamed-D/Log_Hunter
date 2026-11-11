# ▶ 원본: log_hunter/__main__.py
# ▶ python -m log_hunter 호출을 main 함수와 종료 코드로 연결합니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
from .main import main
import sys

sys.exit(main())
