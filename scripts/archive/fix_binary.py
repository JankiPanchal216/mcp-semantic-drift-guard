import re

with open("paper.md", "r+b") as f:
    b = f.read()
    b = re.sub(rb"\(\$V_0[\r\n\s]+ightarrow V_K\$\)", b"($V_0 \\\\rightarrow V_K$)", b)
    f.seek(0)
    f.write(b)
    f.truncate()

print("Binary replace completed with r+b")
