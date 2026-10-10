from pathlib import Path

p = Path("paper.md")
with open(p, "r", encoding="utf-8") as f:
    text = f.read()

text = text.replace("($V_0 \n ightarrow V_K)", "($V_0 \\rightarrow V_K)")
text = text.replace("($V_0 \nightarrow V_K)", "($V_0 \\rightarrow V_K)")

with open(p, "r+", encoding="utf-8") as f:
    f.seek(0)
    f.write(text)
    f.truncate()

print("Fixed line 517-518 arrow notation")
