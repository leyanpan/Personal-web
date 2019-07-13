---
title: Google CTF 2018 Reverse Engineering Problem
---
This is my first blog!

# Summary
I'm a newbie to the Security field and wanted to quickly improve myself in order to comptete in the CTF in the future. Despite being late in the field when compared with my peers, I'm still very eager to learn and believe that I can catch up quickly. This is my first attempt to crack a CTF problem step by step.

In order to record my process of following [TheKidOfArcrania](https://thekidofarcrania.gitlab.io/)'s [write-up](https://thekidofarcrania.gitlab.io/2018/06/25/gctf/) of an Google CTF challenge Reverse Engineering Problem, I decided that I would write down all the new knowledge and difficulties I encountered. Despite the fact that the original author created a "detailed" write-up of his process of solving the problem during his CTF experience, the write-up is definately not detailed enough for a newbie like me to follow along without any external reference. I don't know a lot yet about reverse engineering so this blog is expected to be very very long.


# Decryption
The first thing I would have done when faced with an reverse engineering problem is to load it into IDA pro in our ECE school's servers. However, the connection between China and the VPN server of my college made it impossible to do so. Buying IDA myself costs a ton and IDA free annoys you with "buy IDA pro" everyday.  Therefore, I opened up the executable in Ghidra, a recently released reverse engineering tool created by the NSA that is both open-source and free. However, the most uncomfortable thing about Ghidra to me is that it capitalize all the assembly instructions unlike IDA. I didn't find any configuration related to this problem and finally gave up.

The only segment of code in the original file is an tiny decryptor which creates a new memory mapping and decrypts the main body of the code. However, I'm pretty new to the syscall instructions and spent some effort figuring them out. Thanks to the comments and blog by theKidOfArcrania, I found out the resources for these syscall instructions very quickly.

![Decryption Assembly Code](/files/gctf/decryption_asm.png)

Right at the front we see two calls to the so called `mmap10000` function. It was actually named by me later for better insight. At first I had no idea what this is doing.

![mmap function](/files/gctf/mmap.png)

## syscall

Syscalls are basically Linux Kernel versions of interrupts whose functions are provided directly by the Linux kernel. The type of service is specified in `rax` and corresponds to different syscall functions in the linux kernel source code. The return value of the function would be stored in `rax`.


An detailed table of Linux syscall for 64-bit systems can be found in a [blog by rchapman](http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/). The command arguments are stored in `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9` respectively.

As an example, considered the `mmap` function invoked here by the program.
The original declaration of the mmap function is 
```c
void *mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset);
```
and the syscall number is 9 for mmap.

Therefore, `eax = 9`, `start` is stored in `rdi`, `length` is stored in `rsi`, `prot` is stored in `rdx`,  `fd` is stored in `r8`, and `offset` is stored in `r9`.

## mmap
So what on earth is this mmap thing? A wikipedia search tells me that:

>In computing, mmap(2) is a POSIX-compliant Unix system call that maps files or devices into memory. It is a method of memory-mapped file I/O. It implements demand paging, because file contents are not read from disk directly and initially do not use physical RAM at all. The actual reads from disk are performed in a "lazy" manner, after a specific location is accessed.

So OK, its maps a file into memory. But still I know nothing about paging as I haven't yet taken any OS class, and I found it very hard to understand what this is saying without some basic knowledge about memory paging. So as usual, I googled a lot and finally gained some brief insight.

### Very Brief Introduction to Paging

_This summary is based on personal understanding and may contain severe errors._

Once upon a time when paging didn't exist yet, people (operating systems) struggle to allocate memory for different segments of a program. Programmers need to keep track of different segments carefully as they are located separately in the physical RAM. But BANG! Paging came and saved them all. 

The core of paging: __divide both the virtual and physical memory into equally sized "pages" and use a page as the smallest unit for memory space allocation. The pages of a single program can be located anywhere in the physical RAM without the need for the program itself to keep track of.__

Purpose of paging:
    * Removes the limit of the maximum size of an program.
    * Removes the existance of "Memory Fragments" as each page can always be assigned upon request to any program reguardless of they requested size
    * Makes life _far_ easier for programmers
    * Allows different processes to share the same page of memory

For each process, they system presents a linear address space composed of different pages. Each time the process attemps to access a virtual memory location, it provides a page number and offset. Then, the page number is sent to a hardware called the Memory Management Unit (MMU). The MMU stores a page table which translates the virtual page number of each process to physical page number in the phisical RAM. While the process sees the address space as a continuous memmory space, the different pages of a process may be separated in the Physical RAM. 

These pages may not even be existant in Physical RAM all the time. If you're loading a large executable file you probably would not want to load all of its components when it starts as it would be incredibly slow. It is very logical to load these components only when they're actually used. This is just what disk pages does. Some of the virtual memory pages of a program may be stored on the disk. When the process actually access this page, an interrupt is triggered and the CPU loads the page from the disk to memory. If the memory is full, the CPU would store another page into the disk using an smart algorithm.

## mmap continued
So mmap maps a part of the hard drive (a file in particular) into the virtual memory spaces. Similar to disk pages, a page is only loaded into physical RAM when the program tries to access it. Let's go back to the original declaration of mmap:

```c
void *mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset);
```
Refering to the [linux man page for mmap](http://man7.org/linux/man-pages/man2/mmap.2.html), `addr = NULL` means that the system would decide the location of the new mapping, `length = 0x10000` represents the size of the new mapping, `prot = PROT_READ | PROT_WRITE | PROT_EXEC` means that the new mapping can be freely accessed in any means. `flags = MAP_ANONYMOUS | MAP_PRIVATE` means that the new mapping would be intialized to zero and changes are not visible to other process accessing the same file. The `fd` argument is also ignored due to the `MAP_ANONYMOUS` flag. `offset` is set to zero which I believe needs no further explaination.

In conclusion, the two calls to the function create two empty mappings each of size 0x10000, one for the stack and the other for storing the decrypted main body of the program.

## Decryption loop

The decryption loop is very straight forward, treating memory as 8-byte integers and xoring them with `rax`, initialized to `0x1122334455667788` at the beginning of the program. Therefore, I copied the hex string into a file and wrote this python program very intuitively:

``` python
key = [x * 0x11 for x in range(8)]
hexfile = open('hex', 'r')
hexstr = hexfile.read().split(' ')
binfile = open('bin_decrypt', 'wb')
bins = []
for i in range(len(hexstr)):
    bins.append(int(hexstr[i], 16) ^ key[i % 8])

binfile.write(bytes(bins))
```

Interestingly, in python 2 the bytes type would be expressed as huge 8-bit interger list in human readable format, while in python 3 this program would output a binary string as expected. How annoying are these differences...

So, I happily ran the program and loaded the result into Ghidra. However, the binary file was nonsense and I wondered for a long time, checking whether I've made any silly bug in my python code. Finally I gave up thinking myself and read the code in te original blog post. Interestingly, he used `0x8877665544332211` instead of `0x1122334455667788` as the decryption key. He also left a (misleading) comment:

>because I still can't seem to figure out little endian from big endian!!

Therefore, I spent a lot of my time searching about systems that use small endian and systems that use big endian. The conclusion was that it makes no sense for this particular system to use big endian as almost all modern systems use small endian. This made a whole fuss over my head and after about half an hour I finally realized that the difference between the assembly and my python program is that the assembly treats memory as integers, which would flip them over before performing the xor operation and flip them over again before storing them.

So a small change would do the deal and the final program was as such:

``` python
key = [x * 0x11 for x in range(8,0,-1)]
hexfile = open('hex', 'r')
hexstr = hexfile.read().split(' ')
binfile = open('bin_decrypt', 'wb')
bins = []
for i in range(len(hexstr)):
    bins.append(int(hexstr[i], 16) ^ key[i % 8])

binfile.write(bytes(bins))
```
I loaded the result into Ghidra again and Yeah! I've finished 1/10 of following the Write-up!!!

# Anti Debug

At the start of the decrypted program there is a piece of code like this:

![Anti-Debug](/files/gctf/Anti-debug.png)

This code is pretty typical misleading self-modifying code in order to increase the difficulty of reverse engineering. The `INT 3` instruction is simply there to fool people as the return address is already poped out in `POP RBX` and the last `RET` would return directly back to the main program flow. What makes it difficult for me is the instruction modification at instruction 27. It changes eax from 0xe7 to 0x65, or from syscall_exit_group() to syscall_ptrace(). Anyone with basic knowledge would know that the program would not want to exit now. What fuzzed me is this note from an reverse engineering class I've audited:

>From the Intel architecture manuals:
>Intel® 64 and IA-32 Architectures Software Developer's Manual: Volume 3A: System Programming Guide, Part 1, pp. 10-124 - 10-125
>For Intel486 processors, a write to an instruction in the cache will modify it in both the cache and memory, but if the instruction was prefetched before the write, the old version of the instruction could be the cone executed. To prevent the old instruction from being executed, flush the instruction prefetch unit by coding a jump instruction immediately after any write that modifies an instruction.

I wondered whether the mov instruction would be prefectched and eax would not be changed. So I went to the actually intel manual and found out this just two paragraphs above the noted paragraph.

>A write to a memory location in a code segment that is currently cached in the processor causes the associated cache line (or lines) to be invalidated. This check is based on the physical address of the instruction. In addition, the P6 family and Pentium processors check whether a write to a code segment may modify an instruction that has been prefetched for execution. If the write affects a prefetched instruction, the prefetch queue is invalidated. This latter check is based on the linear address of the instruction. For the Pentium 4 and Intel Xeon processors, a write or a snoop of an instruction in a code segment, where the target instruction is already decoded and resident in the trace cache, invalidates the entire trace cache. The latter behavior means that programs that self-modify code can cause severe degradation of performance when run on the Pentium 4 and Intel Xeon processors.

__tl;dr Modern processors have ways to negate the effect of prefetching.__

The rest is easy. According to the man [page for ptrace](http://man7.org/linux/man-pages/man2/ptrace.2.html), this is a call to ptrace with argument `PTRACE_DETACH` to shrug off any debugger.

# Fork
Very soon comes a system call to fork. Fork is a very common function in linux which creates a subprocess with the same state as the parent except for the return value of the fork function. The child PID is returned to the parent and 0 is returned to the child. Intuitively, I would follow the parent's path first.

## Parent
In the original blog the author actually described this branch as the child branch, which I believed is a mistake, so I will keep my opinion here that this is the parent process as it doesn't matter much. 

Here the program became very happy with syscalls and the linux man pages became my best friends.



