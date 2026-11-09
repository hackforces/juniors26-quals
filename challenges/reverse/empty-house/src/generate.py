from pathlib import Path
import zipfile

def build(flag, root):
    root.mkdir(parents=True, exist_ok=True)
    key = 0x5A
    blob = bytes(ord(c) ^ key for c in flag)
    program = '''# Recovered from the pocket computer\nblob = %r\nkey = 0x5a\nprint("".join(chr(x ^ key) for x in blob))\n''' % blob
    with zipfile.ZipFile(root / 'empty-house.zip', 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('pocket_computer.py', program)
        z.writestr('README.txt', 'The device is offline. Its only recovered program is enclosed.\n')
