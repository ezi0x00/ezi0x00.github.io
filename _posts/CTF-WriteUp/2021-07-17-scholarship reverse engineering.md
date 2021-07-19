---
title: "CyberTalents Scholarship - Reverse Engineering CTF"
classes: wide
header:
  teaser: /assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/banner.png
ribbon: MidnightBlue
description: "This CTF is for DFIR Scholarship program to test the participant's technical skills. about a list of challenges in Reverse Engineering category"
categories:
  - CTF-WriteUp
toc: true
---
<span style="color: #909090">Category: Malware Reverse Engineering</span>

# r0t4t0r - easy:

> One more rotation please. 
>

by reading the decompiled code:

[![1](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/1.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/1.png)

we notice that it takes 31 characters of input
```
v5 = 0;
scanf("%30s", &v7[8]);
while ( v5 < 30 )
```
and saved the encrypted password on stack: 

[![2](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/2.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/2.png)

The loop in main function takes every character of your input, passt it as argument in encrypt function `sub_401550` and compare with the saved encrypted password

[![3](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/3.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/3.png)

The encryption function is rotating the bits left by 2 positions: 

[![4](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/4.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/4.png)

because it's what got compared in the loop, this is the script I used to reversed it:

```
encpwd = b''.join([p64(0xcdd0cced9d85b199), p64(0xccd1d0d1c0c97de5), p64(0xcdd07dd199cc317d), p32(0xccc8c47d), p16(0xf5d0), b'\x00'])
bytes([((i << 6)&255) | ( i >> 2) for i in encpwd])

```
flag: 
```
flag{34sy_r0t4t3_L3ft_4s_1234}
```


# Assembly Master - easy: 

> We all love assembly.
>

[![5](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/5.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/5.png)

```
x:
        .ascii  "v\200suizgahMsMa{\177d\200wMl}bMq|s\200\200w~uwo"
.LC0:
        .string "Wrong flag "
.LC1:
        .string "correct flag :D "
```
is just variables equal strings but focus in first string.

```
Secret_Checker:
        push    rbp
        mov     rbp, rsp
        sub     rsp, 32
        mov     QWORD PTR [rbp-24], rdi
        mov     DWORD PTR [rbp-4], 0
        jmp     .L2
```

constant strings after move to memory adress, it jump to .L2

```
.L2:
        cmp     DWORD PTR [rbp-4], 32
        jle     .L5
        mov     edi, OFFSET FLAT:.LC1
        call    puts
        mov     eax, 1
```
it compare input with 32 characters if lower than jump to .L5 another it print `correct flag :D`

```
.L5:
        mov     eax, DWORD PTR [rbp-4]
        movsx   rdx, eax
        mov     rax, QWORD PTR [rbp-24]
        add     rax, rdx
        movzx   eax, BYTE PTR [rax]
        xor     eax, 19
        movsx   eax, al
        lea     edx, [rax+1]
        mov     eax, DWORD PTR [rbp-4]
        cdqe
        movzx   eax, BYTE PTR x[rax]
        movzx   eax, al
        cmp     edx, eax
        je      .L3
        mov     edi, OFFSET FLAT:.LC0
        call    puts
        mov     eax, 1
        jmp     .L4
```

it's loop takes every byte of input and xor with `19` then jump to .L3 to add one like this:

```
(input[i]^19)+1 
```

So we have a constant it's in x variable: 
```
v\200suizgahMsMa{\177d\200wMl}bMq|s\200\200w~uwo
```

so make it like math equation and inverse it like:
```
(constant[i]-1) ^ 19 
```
Sol:
first we need convert this characters to bytes use this script: 
```
string = "v\200suizgahMsMa{\177d\200wMl}bMq|s\200\200w~uwo"
arr = bytes(string, 'utf-8')
for byte in arr:
    print(byte, end=' ')
print("\n")
```

then this script to print flag: 
```
byte_array=[118,194,128,115,117,105,122,103,97,104,77,115,77,97,123,127,100,194,128,119,77,108,125,98,77,113,124,115,194,128,194,128,119,126,117,119,111]
number = 19
flag = ''
for i in byte_array:
    i-=1
    flag += chr(i ^ number)
print("Crypto{{{}}}".format(flag))
```
flag:
```
flag{just_a_simple_xor_challenge}
```

# Dumper - easy:

> Another executable dumped from memory.
>

Read the written description, you will find that it is the solution
pe file is dumped from the memory and we should fix it.

open file in PE-bear:

[![6](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/6.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/6.png)

the file is unmaped from hard disk to make this file maped as pe it should follow the partition alignment value and not the file alignment.

So solution is make Raw Addr = Raw Size and Virtual Addr Virtual Size

[![7](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/7.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/7.png)

Save and run.
flag: 
```
flag{Successfully_Done_123456}
```

# ezez keygen 2 - medium:

> I want to play this game with the admin account, could you help me?
>
> there are WriteUp[WriteUp](https://t1m3m.github.io/posts/cybertalents-cairo-university-2019-ctf/#ezez-keygen-2) to it 

My solution: 


by reading the decompiled code:

[![8](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/8.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/8.png)

it takes two arguments and saved first in `s1` and second in `v5`:

```
if ( argc > 2 )    
    s1 = strdup(argv[1]);
    v5 = strdup(argv[2]);
```

and then pass the arguments to `check` function to check if it true or not and compare if s1 equal `4dminUser31337`: 

```
if ( (unsigned int)check(s1, v5) != 1 || strcmp(s1, "4dminUser31337") )
    {
      puts("unrecognized user");
      exit(-1);
    }
    printf("flag is: flag{%s}\n", v5);
    result = 0;
  }
  else
  {
    puts("usage: ./ezez_keygen2 username serial");
    result = -1;
  }
```

so we get first argument let's move on to `check` function: 

[![9](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/9.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/9.png)

notice that first check if first argument equal 30 bytes and second is 60 and it shoud be as this

```
  if ( v4 > 0x1E || v5 > 0x3C )
    return 0xFFFFFFFFLL;

    // 0x1E in hex = 30 in decimal , 0x3C = 60
```

then it check if the second argument is greater than first or not and shoud be as this

```
  if ( v5 >> 1 != v4 )
    return 0xFFFFFFFFLL;
```

then it pass the second argument to `getuser` function and it return string then it check if identical to the first argument or not. 

```
  v3 = getuser(a2);
  if ( !strcmp(v3, a1) )
    result = 1LL;
  else
    result = 0xFFFFFFFFLL;
```

let's move on to `getuser` function: 

[![10](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/10.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/10.png)

it's get index of second argument letter in LTable and HTable 

LTable and HTable from data section :

```
LTable = "AFECWQPXIGJTUBN%"
HTable = "cpqowuejfnvhzbx$"
```

and pass it to `getbin` to convert it to binary 


This was just a clarification of some things, but there is a previous writeup for this, so you will not need my script, because the script in the previous article explains every part of what it wrote.

# Kill Joy - medium:

>Let's focus on the basic again.
>

first i can't find the main function so i went to sleep and woke up completed a solution.

to find main function run the program it will print:
```
Not what i was searching for :(
```

in ida pro press `sheift + f12` to view strings and `ctrl + f` to search about `Not what i was searching for :(` press `x`  to know ref about this print cause the program will start from main so this string it should in main function then enter to go to main function 

[![11](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/11.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/11.png)

[let's go](https://www.youtube.com/watch?v=dUHPZqJ5XOc)

by 

by reading the decompiled code:

[![12](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/12.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/12.png)

i noticed there are API'S functions so let's what's doing:

first:
```
//PROCESSENTRY32W
//Describes an entry from a list of the processes residing in the system address space when a snapshot was taken.
```

second: 
```
//hSnapshot
It means it will create a snapshot of the processes in the system. 
```

third:
```
//j_CreateToolhelp32Snapshot
//Takes a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes.
```

In short, what these functions do is: 
1 - collect and return to all processes in the system to the snapshot 
2 - gets the information of the first process in the snapshot 
3 - gets the executable name for the current process like `Kill_Joy.exe`

after get the `Kill_Joy.exe`, it do for loop to shift the name:

```
  do
  {
 if ( GetCurrentProcessId() == pe.th32ProcessID )
    {
      Dest = (char *)malloc(0x32ui64);
      v8 = wcstombs(Dest, pe.szExeFile, 0x32ui64);
      v9[8] = 0;
      for ( j = 0; j < 8; ++j )
      {
        v9[j] = 0;
        v9[j] |= Dest[4 * j] << 24;
        v9[j] |= Dest[4 * j + 1] << 16;
        v9[j] |= Dest[4 * j + 2] << 8;
        v9[j] |= Dest[4 * j + 3];
      }
```
i noticed with something, Flag is the name of the file <flag{fl4g}.exe>, Usually it will be 32 characters, There is a hardcoded value of about 16 digits, It encrypts the filename by inverse, it takes a block of 4 letters with 4 letters, and so on, and compares the output with another hash hardcode.

so we need the hardcoded hash to inverse encryption algorithm (we need know what's encryption algorithm) 

We got a hint:

> 0x9E3779B9 ??? Google is your friend :D 
>

My guess was right, I suspected it was the XTEA algorithm.

So get the cipther from: 

[![13](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/13.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/13.png)

The key: 
breakboint on the call: 

[![14](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/14.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/14.png)

get the argument value as a key: 

[![15](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/15.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/15.png)


then simulate the decrypt from google: 

```
#include <stdio.h>
#include <stdint.h>


void decrypt(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*num_rounds;
    for (i=0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0]=v0; v[1]=v1;
}





int main()
{
    uint32_t enc_flag[8] = { {0xD6F74320, 0x636A7B0A},
            {0xEEC58E45, 0x5F1E3AF5},
            {0x14D72088, 0x819BF516},
            {0x10A4D83A, 0x2C1001E7}};
    static uint32_t tea_key[4] = {0x34561234, 0x111F3423, 0x01333337, 0x34D57910};
    for (int i = 0;i < 8;i += 2)
    {
        decrypt(enc_flag + i, tea_key);
    }
    printf("[+] Flag: ");
    for (int i = 0;i < 8;i++)
    {
        printf("%c", (enc_flag[i] >> (24)));
        printf("%c", (enc_flag[i] >> (16)));
        printf("%c", (enc_flag[i] >> (8)));
        printf("%c", (enc_flag[i] >> (0)));
    }
}
```
flag: 
```
flag{th4ts_h0w_y0u_surv1v3_}
```

# PE M0nSt3r: 

> Better recognize art, cause I don't forget names.  
>

The Art: 

[![16](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/16.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/16.png)

[![shit](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/shit.jpg)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/shit.jpg)


At first, I didn't know what to do, so I followed a normal methodological method, such as Malware's analysis, and when I got to checking the import function, I found the thread that told me what to do.

[![17](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/17.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/17.png) | [![18](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/shit.jpg)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/18.png)

Focus on: 
```
CreateProcessW
VirtualAllocEx
ZwUnmapViewOfSection 
NtUnmapViewOfSection 
WriteProcessMemory
SetThreadContext
ResumeThread 
```

let's learn something new in process injection technique it's called `process hollowing`:

>Process hollowing occurs when a challenge unmaps (hollows out) the legitimate code from memory of the target process, and overwrites the memory space of the target process with a malicious executable.
>
>

[![19](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/19.gif)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/19.gif) 

Process hollowing is commonly performed by creating a process in a suspended state then unmapping/hollowing its memory, which can then be replaced with malicious code. 
A victim process can be created with native Windows API calls such as CreateProcess, which includes a flag to suspend the processes primary thread.
At this point the process can be unmapped using APIs calls such as ZwUnmapViewOfSection or NtUnmapViewOfSection before being written to, realigned to the injected code, and resumed via VirtualAllocEx, WriteProcessMemory, SetThreadContext, then ResumeThread respectively.

To get started, we want to set a breakpoint (pause execution) when the code calls CreateProcessW from the Windows API. We saw in Process Monitor that pe monster.exe was created as process child, and it was likely done using that call. In order to do that in x64dbg, hit in command `bp CreateProcessW`

started :

[![19](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/19.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/19.png) 

Run until execute CreateProcessW to see a process child: 

[![20](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/20.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/20.png) 

So how does a malicious program hollow out a process? It makes a few tell tale API calls. We have already seen the first one `CreateProcessW`

Other calls include:
> NtUnmapViewOfSection: Unmap the memory occupied by the newly spawned process so that there is nothing in the newly spawned process.
>
> VirtualAllocEx / VirtualAlloc: Allocate enough memory to put the bad code in
>
> WriteProcessMemory: Write the malicious code into the vacant memory space
>
> GetThreadContext: Get the details of the new process so that the original process can modify the entry point of the newly spawned / hollow process. When the challenge resumes the hollowed out process with its malicious code in it, Windows will be expecting the code to start at a certain place. The challenge needs to adjust this for the new code it has just put in. GetThreadContext allows the challenge to get those details so that it can edit them.
>
> SetThreadContext: Change the entry point of the hollowed out process to correspond with the malicious code now living inside of it.
>
> ResumeThread: Run the hollowed out process that now contains malicious code.
>
We want to see if we can see the code that gets written into the process so that maybe we can isolate it and examine it further. 

So, we will need to set a breakpoint before WriteProcessMemory.  We will follow the same procedure as we did for CreateProcessW. 
Once you have set that break point, hit F9 to resume execution. If we step out into Process Explorer, we can see the suspended pe monster.exe process:

Let's breakboint:

you can hit ctrl+g and search about functions we mentioned: 

The challenge first creates a new process to host the malicious code in suspended mode this is done by calling CreateProcessW and setting the Process Creation Flag to CREATE_SUSPENDED (0x00000004). 
The primary thread of the new process is created in a suspended state and does not run until the NtResumeThread function is called.

[![21](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/21.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/21.png) 

Next, the challenge needs to swap out the contents of the legitimate file with its another exe. 
This is done by unmapping the memory of the target process by calling either ZwUnmapViewOfSection or NtUnmapViewOfSection. This two APIs release all memory pointed to by a section.

[![22](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/22.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/22.png) 

Now that the memory is unmapped, the loader performs VirtualAllocEx to allocate new memory for the another pe. Uses ZwWriteVirtualMemory challenge can then write each of the challenge's sections to the target process space.

[![23](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/23.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/23.png) 

The challenge calls SetThreadContext to point the Entrypoint to a new code section that it has written. In the end, the challenge resumes the suspended thread by calling NtResumeThread to take the process out of suspended state.

[![24](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/24.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/24.png) 

> Repeat it with WriteProcessMemory or WriteVirtualMemory and VirtualAlloc. The order does not matter because that process will take its course in the implementation.
>

Then run until arrive to NtResumeThread, you will find the unpacking file write in buffer adress (argument of WriteProcessMemory), right click on adress choose follow in memory map and right click dump file.

[![25](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/25.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/25.png) | [![26](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/26.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/26.png) 
 
when we run the unpacking we found it's crashed so let's open it in PE-bear: 

[![27](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/27.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/27.png)

oh the entrypoint is equal = 0.

do you remember when run the first stage and print 
```
[+] You will need this: 5344
```

so i think this the entrypoint, let's try. 

[![28](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/28.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/28.png)

Now we are ready to reverse it.

by decompiled code notice something it's TEA algorithm:

[![29](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/29.png)](/assets/images/CTF-WriteUp/CyberTalentsScholarShip-ReverseEngineering/29.png)

so let's repeat process of kill joy but change decrypt function because Kill_Joy it's XTEA 
:

```
#include <stdio.h>
#include <stdint.h>
#include <windows.h>


void decrypt(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0xC6EF3720, i;  /* set up; sum is 32*delta */
    uint32_t delta = 0x9E3779B9;                     /* a key schedule constant */
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];   /* cache key */
    for (i = 0; i < 32; i++) {                         /* basic cycle start */
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        sum -= delta;
    }                                              /* end cycle */
    v[0] = v0; v[1] = v1;
}

int main()
{
    uint32_t enc_flag[8] = {{0x21C2FB7C, 0xC553E97B},
      {0x9E893411, 0xFF5A7E60},
      {0xB12CA755, 0xA5D55898},
      {0x8A08537A, 0x663511D1} };
    static uint32_t tea_key[4] = {0x34561234, 0x111F3423, 0x34D57910, 0x00989034 };
    for (int i = 0;i < 8;i += 2)
    {
        decrypt(enc_flag + i, tea_key);
    }
    printf("[+] Flag: ");
    for (int i = 0;i < 8;i++)
    {
        printf("%c", (enc_flag[i] >> (24)));
        printf("%c", (enc_flag[i] >> (16)));
        printf("%c", (enc_flag[i] >> (8)));
        printf("%c", (enc_flag[i] >> (0)));
    }
}

```

flag:
```
flag{W3Lc0m3_t0_r3v3rs3_L4nd-_-}
```


Thanks for reading, Suggestions & Feedback are appreciated !