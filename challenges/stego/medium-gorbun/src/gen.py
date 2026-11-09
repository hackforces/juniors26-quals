import struct,wave
from pathlib import Path
def build(flag,root):
 out=root/'download';out.mkdir(parents=True,exist_ok=True);bits=''.join(f'{x:08b}' for x in flag.encode()+b'\0'); samples=[]
 for i in range(16000):
  v=((i*313)%24000)-12000
  if i<len(bits):v=(v&~1)|int(bits[i])
  samples.append(v)
 with wave.open(str(out/'bell.wav'),'wb') as w:w.setparams((1,2,8000,0,'NONE',''));w.writeframes(struct.pack('<'+'h'*len(samples),*samples))
