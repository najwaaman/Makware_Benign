"""Automated verification test for Streamlit Dashboard navigation."""
import sys
import io
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from streamlit.testing.v1 import AppTest

def test_all_pages():
    print("=" * 60)
    print(" VERIFYING STREAMLIT DASHBOARD PAGES ")
    print("=" * 60)

    at = AppTest.from_file("dashboard/app.py", default_timeout=30)
    at.run()
    assert not at.exception, f"Exception on initial page: {at.exception}"

    pages = [
        "🏠 Detection",
        "📊 Dataset",
        "🔎 EDA",
        "🧬 Feature Engineering",
        "🎯 Feature Selection",
        "🤖 Models",
        "📈 Evaluation",
        "🔬 Explainability",
        "📁 Batch Analysis",
        "ℹ️ About",
    ]

    for p in pages:
        at.sidebar.radio[0].set_value(p).run()
        if at.exception:
            print(f"[ERROR] on page {p}: {at.exception}")
            raise at.exception[0]
        print(f"[SUCCESS] Page '{p}' rendered successfully.")

    print("=" * 60)
    print(" ALL PAGES TESTED AND PASSED WITHOUT ERRORS! ")
    print("=" * 60)

if __name__ == "__main__":
    test_all_pages()