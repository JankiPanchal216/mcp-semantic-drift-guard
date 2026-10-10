import re
from pathlib import Path

p = Path("paper.md")
with open(p, "r", encoding="utf-8") as f:
    text = f.read()

# Fix \x08 (backspace) and \r (carriage return) artifacts from python string escapes
text = text.replace("$ ar{W}_e$", "$\\bar{W}_e$")
text = text.replace("(V_0 ightarrow V_K)", "(V_0 \\rightarrow V_K)")

with open(p, "r+", encoding="utf-8") as f:
    f.seek(0)
    f.write(text)
    f.truncate()

print("Cleaned up LaTeX math notation in paper.md")
