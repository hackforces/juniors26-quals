from pathlib import Path
def build(flag,root):
 out=root/'download';out.mkdir(parents=True,exist_ok=True);bits=''.join(f'{x:08b}' for x in flag.encode()+b'\0'); pix=bytearray()
 for i in range(128*128):
  b=int(bits[i]) if i<len(bits) else (i*19)&1;pix.extend((232,194,(87&254)|b))
 (out/'portrait.ppm').write_bytes(b'P6\n128 128\n255\n'+pix)
