import sys
from pathlib import Path

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# Let's inspect how Streamlit renders markdown elements
from streamlit.testing.v1 import AppTest

at = AppTest.from_file("dashboard/app.py", default_timeout=30)
at.run()
print(f"App loaded without exceptions: {not at.exception}")

# Let's inspect the markdown elements rendered on detection page
md_elements = at.markdown
print(f"Total markdown elements: {len(md_elements)}")
for idx, el in enumerate(md_elements):
    val = el.value
    if "<div>" in val or "MALWARE" in val or "BENIGN" in val or "result-glass-card" in val:
        print(f"\n--- Markdown Element #{idx+1} ---")
        print(val[:300])
