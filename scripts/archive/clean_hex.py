from pathlib import Path

p = Path("paper.md")
with open(p, "r", encoding="utf-8") as f:
    text = f.read()

# Replace literal \x08 and \r chars
text = text.replace("\x08ar{W}_e", "\\bar{W}_e")
text = text.replace("\right", "\\right")
text = text.replace("\r", "\n")  # normalize any stray \r

with open(p, "r+", encoding="utf-8") as f:
    f.seek(0)
    f.write(text)
    f.truncate()

print("Cleaned up hex escape characters")
