import glob
import pwn

pwn.context.log_level = "WARN"

proc = pwn.process(glob.glob("/challenge/bab*")[0])
proc.recvuntil(b"first message is")
text = proc.recvuntil(b"What's the decrypted secret?").decode()
decMsg = ""

secret=""

for c in text:
    if c.isdigit():
        decMsg += c
i=0
while i < len(decMsg):
    if decMsg[i] == '1':
        secret += chr(int(decMsg[i:i+3]))
        i+=2
    else:
        secret += chr(int(decMsg[i:i+2]))
        i+=1
    i+=1

proc.sendline(secret.encode())
proc.recvuntil(b"flag is ")
print(proc.recvall(1).decode().strip())
