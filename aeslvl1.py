import pwn #library for exploit tools
import glob #library used to locate our challenge file

print("Don't just copy paste the code!")
exit(0)

pwn.context.log_level = "WARN" #tell pwn tools to only report important stuff

proc = pwn.process(glob.glob("/challenge/bab*")[0]) #start a pwntools process and use global library to locate file
proc.recvuntil(b"first message is") #burn the first part of the challenge output we don't care about
text = proc.recvuntil(b"What's the decrypted secret?").decode() #store output with decimal values we need for decryption

decMsg = "" #blank string to add decimal values to
secret="" #blank string that will eventually hold decrypted secret

#for loop to iterate character by character through our text variable and store the decimal characters
# under the blank string defined earlier
for c in text:
    if c.isdigit():
        decMsg += c
#second loop to iterate through our decimal value string and convert the decimal values to ascii
i=0
while i < len(decMsg):
    if decMsg[i] == '1': #if the character at position i is 1, we know the decimal value we want is 3 characters long
        secret += chr(int(decMsg[i:i+3])) #cast the character at the current position and the next 2 positions (i+3 because the end is exclusive) to an int, then an ascii char
        i+=2 #add to our iterator because we just read the next 2 characters
    else:
        secret += chr(int(decMsg[i:i+2])) #if it doesn't start with 1, we know it is 2 characters long
        i+=1 #add to our iterator because we just read the next character
    i+=1 #add to the iterator as you would any while loop

proc.sendline(secret.encode()) #send the process the secret
proc.recvuntil(b"flag is ") #burn everything that isn't a flag
print(proc.recvall(1).decode().strip()) #grab the flag, convert to ascii and strip the trailing \n
