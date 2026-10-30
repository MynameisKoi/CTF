# TryHackMe — Classic Passwd (Complete Technical Write-Up)

- **Room**: [Classic Passwd](https://tryhackme.com/room/classicpasswd)
- **Category**: Reverse Engineering / ELF Binary Analysis (`x86_64`) & Buffer Overflow
- **Artifacts in Repo**:
  - [`Challenge_1609966715991.Challenge`](./Challenge_1609966715991.Challenge) (`16,928` bytes, 64-bit ELF PIE executable)
  - [`solve.py`](./solve.py) (Automated password & flag extractor / runner)

---

## 1. Initial Binary Triage (`file`, `rabin2 -I`, `rabin2 -z`)

First, we inspected the binary using `file` and `rabin2`:

### Command Executed
```bash
file Challenge_1609966715991.Challenge \
  && rabin2 -I Challenge_1609966715991.Challenge \
  && rabin2 -z Challenge_1609966715991.Challenge
```

### Output
```text
Challenge_1609966715991.Challenge: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b80ce38cb25d043128bc2c4e1e122c3d4fbba7f7, for GNU/Linux 3.2.0, not stripped
arch     x86
bits     64
canary   false
class    ELF64
compiler GCC: (Debian 10.2.0-16) 10.2.0
nx       true
pic      true
relro    partial
stripped false

nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00002004 0x00002004 22  23   .rodata ascii Insert your username:
1   0x0000201e 0x0000201e 8   9    .rodata ascii \nWelcome
2   0x00002027 0x00002027 21  22   .rodata ascii \nAuthentication Error
3   0x0000203d 0x0000203d 9   10   .rodata ascii THM{%d%d}
```

The binary is **not stripped** (`stripped false`) and has stack canaries disabled (`canary false`). Notice `.rodata` contains `"THM{%d%d}"`, indicating the flag is constructed dynamically from two integer values.

---

## 2. Disassembly & Control Flow Analysis (`radare2`)

Next, we analyzed all functions and disassembled `main`, `sym.vuln`, and `sym.gfl` using `radare2`:

### Command Executed
```bash
r2 -q -e bin.relocs.apply=true -c 'aaa; afl; pdf @ main; pdf @ sym.vuln; pdf @ sym.gfl' Challenge_1609966715991.Challenge
```

### Disassembly of `main` (`0x12f6`)
```x86asm
┌ 31: int main (int argc, char **argv, char **envp);
│           0x000012f6      55             push rbp
│           0x000012f7      4889e5         mov rbp, rsp
│           0x000012fa      b800000000     mov eax, 0
│           0x000012ff      e881feffff     call sym.vuln
│           0x00001304      b800000000     mov eax, 0
│           0x00001309      e87bffffff     call sym.gfl
│           0x0000130e      b800000000     mov eax, 0
│           0x00001313      5d             pop rbp
└           0x00001314      c3             ret
```
`main` calls `sym.vuln()` (`0x1185`) and, if `sym.vuln()` returns without calling `exit(0)`, immediately calls `sym.gfl()` (`0x1289`) to print the flag.

---

### Disassembly of `sym.vuln` (`0x1185`)
```x86asm
┌ 260: sym.vuln ();
│           0x00001185      55             push rbp
│           0x00001186      4889e5         mov rbp, rsp
│           0x00001189      4881ecc002..   sub rsp, 0x2c0
│           0x00001190      48b84d6164..   movabs rax, 0x207962206564614d ; 'Made by '
│           0x0000119a      488945f3       mov qword [var_dh], rax
│           0x0000119e      c745fb346e..   mov dword [var_5h], 0x6e6f6e34 ; '4non'
│           0x000011a5      c645ff00       mov byte [var_1h], 0
│           0x000011a9      48b8687474..   movabs rax, 0x2f2f3a7370747468 ; 'https://'
│           0x000011b3      48ba676974..   movabs rdx, 0x632e627568746967 ; 'github.c'
│           0x000011bd      488945d0       mov qword [var_30h], rax
│           0x000011c1      488955d8       mov qword [var_28h], rdx
│           0x000011c5      48b86f6d2f..   movabs rax, 0x69626f306e2f6d6f ; 'om/n0obi'
│           0x000011cf      488945e0       mov qword [var_20h], rax
│           0x000011d3      66c745e87434   mov word [var_18h], 0x3474  ; 't4'
│           0x000011d9      c645ea00       mov byte [var_16h], 0
│           0x000011dd      48b8414742..   movabs rax, 0x6435736a36424741 ; 'AGB6js5d'
│           0x000011e7      488985c2fd..   mov qword [s2], rax
│           0x000011ee      c785cafdff..   mov dword [var_236h], 0x476b6439 ; '9dkG'
│           0x000011f8      66c785cefd..   mov word [var_232h], 0x37   ; '7'
│           0x00001201      488d3dfc0d..   lea rdi, str.Insert_your_username: ; "Insert your username: "
│           0x0000120d      e83efeffff     call sym.imp.printf
│           0x00001212      488d85d0fd..   lea rax, [src]
│           0x00001228      e843feffff     call sym.imp.__isoc99_scanf ; scanf("%s", src)
│           0x00001241      e8eafdffff     call sym.imp.strcpy         ; strcpy(dest, src)
│           0x0000125a      e801feffff     call sym.imp.strcmp         ; strcmp(dest, s2)
│           0x0000125f      85c0           test eax, eax
│       ┌─< 0x00001261      750e           jne 0x1271
```

Looking at lines `0x11dd`–`0x11f8`, `sym.vuln` constructs the target comparison string `s2` on the stack in little-endian:
- `0x6435736a36424741` → `"AGB6js5d"`
- `0x476b6439` → `"9dkG"`
- `0x0037` → `"7\x00"`
- Combined string `s2`: **`AGB6js5d9dkG7`**

*(Note: Because `dest` is at `rbp - 0x2c0` and `s2` is at `rbp - 0x23e` (`130` bytes above `dest`), you can also pass the check via a stack buffer overflow by sending `130` bytes of `A`s so `strcpy(dest, src)` overwrites `s2` with the tail of `dest`, or simply provide the exact string `AGB6js5d9dkG7`).*

---

### Disassembly of `sym.gfl` (`0x1289`)
```x86asm
┌ 109: sym.gfl ();
│           0x00001289      55             push rbp
│           0x0000128a      4889e5         mov rbp, rsp
│           0x0000128d      4883ec10       sub rsp, 0x10
│           0x00001291      c745fcd5c8..   mov dword [var_4h], 0x52c8d5
│       ┌─< 0x00001298      eb4f           jmp 0x12e9
│      ┌──> 0x0000129a      817dfc788a..   cmp dword [var_4h], 0x638a78
│     ┌───< 0x000012a1      7542           jne 0x12e5
│     │╎│   0x000012a3      c745f87414..   mov dword [var_8h], 0x1474
│    ┌────< 0x000012aa      eb30           jmp 0x12dc
│   ┌─────> 0x000012ac      817df83021..   cmp dword [var_8h], 0x2130
│  ┌──────< 0x000012b3      7523           jne 0x12d8
│  │╎││╎│   0x000012b5      8b55f8         mov edx, dword [var_8h]
│  │╎││╎│   0x000012b8      8b45fc         mov eax, dword [var_4h]
│  │╎││╎│   0x000012bb      89c6           mov esi, eax
│  │╎││╎│   0x000012bd      488d3d790d..   lea rdi, str.THM_d_d        ; "THM{%d%d}"
│  │╎││╎│   0x000012c4      b800000000     mov eax, 0
│  │╎││╎│   0x000012c9      e882fdffff     call sym.imp.printf
```

In `sym.gfl`:
- `var_4h` (`esi`, 1st `%d`) is compared against `0x638a78` = **`6523512`**
- `var_8h` (`edx`, 2nd `%d`) is compared against `0x2130` = **`8496`**
- `printf("THM{%d%d}", 6523512, 8496)` prints: **`THM{65235128496}`**

---

## 3. Verification Execution

```bash
$ chmod +x Challenge_1609966715991.Challenge
$ echo 'AGB6js5d9dkG7' | ./Challenge_1609966715991.Challenge
Insert your username: 
Welcome
THM{65235128496}
```

---

## 4. Final Flag

```text
THM{65235128496}
```
