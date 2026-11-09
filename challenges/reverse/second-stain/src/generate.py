from pathlib import Path
import zipfile

# A deliberately small, documented-but-unexplained bytecode. The participant
# recovers the bytecode semantics from the interpreter rather than guessing data.
def build(flag, root):
    root.mkdir(parents=True, exist_ok=True)
    code = bytearray()
    for i, ch in enumerate(flag.encode()):
        code += bytes((0x10, ch ^ ((i * 17 + 31) & 255), 0x20, i & 255))
    code += b'\xff'
    interpreter = '''import sys
program=open(sys.argv[1], 'rb').read(); expected=[]; pc=0
while pc < len(program):
 op=program[pc]; pc+=1
 if op==0xff: break
 if op==0x10: acc=program[pc]; pc+=1
 elif op==0x20:
  index=program[pc]; pc+=1
  expected.append((index, acc))
 else: raise ValueError('damaged instruction')
candidate=input("last message: ").encode()
ok=len(candidate)==len(expected) and all(candidate[index] ^ ((index*17+31)&255) == value for index,value in expected)
print("message accepted" if ok else "message rejected")
'''
    with zipfile.ZipFile(root/'second-stain.zip','w',zipfile.ZIP_DEFLATED) as z:
        z.writestr('last_log.vm', code)
        z.writestr('watch_runtime.py', interpreter)
        z.writestr('README.txt','The watch was copied byte-for-byte. Its runtime only confirms a complete message; it never displays one.\n')
