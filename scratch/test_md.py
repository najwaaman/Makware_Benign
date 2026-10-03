import textwrap
import sys
import markdown

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

card_cls = "result-glass-card-benign hover-spotlight spotlight-benign"
headline_icon = "🛡️"
headline_text = "BENIGN FILE"
headline_color = "#10B981"
headline_glow = "0 0 22px rgba(16, 185, 129, 0.5)"
threat_badge = "Threat Classification: Clean / Safe Executable"
threat_color = "#6EE7B7"
malware_val_color = "#94A3B8"
benign_val_color = "#10B981"
malware_pct = 0.09
benign_pct = 99.91
confidence = 99.91
cert_level = "High"
model_name = "HistGradientBoosting"
target_file_name = "notepad.exe"

# 1. Old indented with blank lines:
old_code = textwrap.dedent(
    f"""
    <div class="{card_cls}">
        <!-- 1. Headline -->
        <div style="display: flex; align-items: center; justify-content: center; gap: 12px; margin-bottom: 2px;">
            <span style="font-size: 2.3rem; filter: drop-shadow(0 0 8px {headline_color});">{headline_icon}</span>
            <span style="font-size: 2.2rem; font-weight: 900; color: {headline_color}; text-shadow: {headline_glow}; letter-spacing: -0.5px;">{headline_text}</span>
        </div>
        <div style="color: {threat_color}; font-size: 0.95rem; font-weight: 600; margin-bottom: 1.1rem;">
            {threat_badge}
        </div>
        
        <!-- 2. Animated Probability Display (Horizontal Split Bar & 3-Column Metrics with zero gap) -->
        <div style="background: rgba(15, 23, 42, 0.65); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; padding: 1.1rem 1.3rem; margin-bottom: 0.9rem;">
            <div style="margin-bottom: 0.85rem;">
                <div style="display: flex; justify-content: space-between; font-size: 0.82rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.6px; margin-bottom: 6px;">
                    <span style="color: #EF4444;">Malware: {malware_pct:.2f}%</span>
                    <span style="color: #10B981;">Benign: {benign_pct:.2f}%</span>
                </div>
            </div>
        </div>
    </div>
    """
)

print("=== PARSING OLD INDENTED STRING ===")
print(markdown.markdown(old_code))

# 2. Fully unindented string without 4-space indents on lines:
new_code = f"""<div class="{card_cls}">
<div style="display: flex; align-items: center; justify-content: center; gap: 12px; margin-bottom: 2px;">
<span style="font-size: 2.3rem; filter: drop-shadow(0 0 8px {headline_color});">{headline_icon}</span>
<span style="font-size: 2.2rem; font-weight: 900; color: {headline_color}; text-shadow: {headline_glow}; letter-spacing: -0.5px;">{headline_text}</span>
</div>
<div style="color: {threat_color}; font-size: 0.95rem; font-weight: 600; margin-bottom: 1.1rem;">
{threat_badge}
</div>
<div style="background: rgba(15, 23, 42, 0.65); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; padding: 1.1rem 1.3rem; margin-bottom: 0.9rem;">
<div style="margin-bottom: 0.85rem;">
<div style="display: flex; justify-content: space-between; font-size: 0.82rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.6px; margin-bottom: 6px;">
<span style="color: #EF4444;">Malware: {malware_pct:.2f}%</span>
<span style="color: #10B981;">Benign: {benign_pct:.2f}%</span>
</div>
</div>
</div>
</div>"""

print("\n=== PARSING UNINDENTED STRING ===")
print(markdown.markdown(new_code))
