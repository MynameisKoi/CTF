# TryHackMe — Compiled (Complete Technical Write-Up)

- **Room**: [Compiled](https://tryhackme.com/room/compiled)
- **Category**: Reverse Engineering / ELF `x86_64` & `scanf` Format String Parsing
- **Artifacts in Repo**:
  - [`Compiled-1688545393558.Compiled`](./Compiled-1688545393558.Compiled) (`16,568` bytes, 64-bit ELF PIE executable, not stripped)
  - [`solve.py`](./solve.py) (Automated `.rodata` extractor and binary verifier)

---

## 1. Initial Triage (`file`, `strings`, `.rodata`)

Running `file`, `strings`, and `objdump -s -j .rodata` on `Compiled-1688545393558.Compiled`:

```bash
file Compiled-1688545393558.Compiled && objdump -s -j .rodata Compiled-1688545393558.Compiled
```

```text
Compiled-1688545393558.Compiled: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=06dcfaf13fb76a4b556852c5fbf9725ac21054fd, for GNU/Linux 3.2.0, not stripped

Contents of section .rodata:
 2000 01000200 50617373 776f7264 3a200044  ....Password: .D
 2010 6f596f75 4576656e 25734354 46005f5f  oYouEven%sCTF.__
 2020 64736f5f 68616e64 6c65005f 696e6974  dso_handle._init
 2030 00436f72 72656374 21005472 79206167  .Correct!.Try ag
 2040 61696e21 00                          ain!.
```

Note how `.rodata` hides two strings (`"__dso_handle"` at `0x201e` and `"_init"` at `0x202b`) that look identical to standard compiler-generated ELF symbol names so they blend into `strings` output!

---

## 2. Disassembly of `main` (`0x1169`)

```bash
objdump -d -M intel -j .text Compiled-1688545393558.Compiled
```

```assembly
0000000000001169 <main>:
    1169: 55                            push   rbp
    116a: 48 89 e5                      mov    rbp,rsp
    116d: 48 83 ec 40                   sub    rsp,0x40
    1171: 48 b8 53 74 72 69 6e 67 73 49 movabs rax,0x4973676e69727453 ; "StringsI"
    117b: 48 ba 73 46 6f 72 4e 6f 6f 62 movabs rdx,0x626f6f4e726f4673 ; "sForNoob"
    1185: 48 89 45 c0                   mov    QWORD PTR [rbp-0x40],rax
    1189: 48 89 55 c8                   mov    QWORD PTR [rbp-0x38],rdx
    118d: 66 c7 45 d0 73 00             mov    WORD PTR [rbp-0x30],0x73 ; "s\0"
    ...
    11b6: 48 8d 45 e0                   lea    rax,[rbp-0x20]
    11ba: 48 89 c6                      mov    rsi,rax
    11bd: 48 8d 05 4b 0e 00 00          lea    rax,[rip+0xe4b]        # 200f "DoYouEven%sCTF"
    11c4: 48 89 c7                      mov    rdi,rax
    11c7: b8 00 00 00 00                mov    eax,0x0
    11cc: e8 7f fe ff ff                call   1050 <__isoc99_scanf@plt>
    11d1: 48 8d 45 e0                   lea    rax,[rbp-0x20]
    11d5: 48 8d 15 42 0e 00 00          lea    rdx,[rip+0xe42]        # 201e "__dso_handle"
    11dc: 48 89 d6                      mov    rsi,rdx
    11df: 48 89 c7                      mov    rdi,rax
    11e2: e8 59 fe ff ff                call   1040 <strcmp@plt>
    11e7: 85 c0                         test   eax,eax
    11e9: 78 1a                         js     1205 <main+0x9c>
    11eb: 48 8d 45 e0                   lea    rax,[rbp-0x20]
    11ef: 48 8d 15 28 0e 00 00          lea    rdx,[rip+0xe28]        # 201e "__dso_handle"
    11f6: 48 89 d6                      mov    rsi,rdx
    11f9: 48 89 c7                      mov    rdi,rax
    11fc: e8 3f fe ff ff                call   1040 <strcmp@plt>
    1201: 85 c0                         test   eax,eax
    1203: 7e 46                         jle    124b <main+0xe2>       # "Try again!"
    1205: 48 8d 45 e0                   lea    rax,[rbp-0x20]
    1209: 48 8d 15 1b 0e 00 00          lea    rdx,[rip+0xe1b]        # 202b "_init"
    1210: 48 89 d6                      mov    rsi,rdx
    1213: 48 89 c7                      mov    rdi,rax
    1216: e8 25 fe ff ff                call   1040 <strcmp@plt>
    121b: 85 c0                         test   eax,eax
    121d: 75 16                         jne    1235 <main+0xcc>       # "Try again!"
    121f: 48 8d 05 0b 0e 00 00          lea    rax,[rip+0xe0b]        # 2031 "Correct!"
    1226: 48 89 c7                      mov    rdi,rax
    1229: b8 00 00 00 00                mov    eax,0x0
    122e: e8 fd fd ff ff                call   1030 <printf@plt>
```

### Analysis of the Logic
1. **Decoy Stack String (`[rbp-0x40]`):** Initializes `"StringsIsForNoobs"`, which is never referenced again.
2. **`scanf("DoYouEven%sCTF", buf)` (`0x11cc`):**
   - `scanf` first requires the literal prefix `"DoYouEven"` on `stdin`.
   - Next, the `%s` conversion specifier greedily consumes all remaining non-whitespace characters into `buf` (`[rbp-0x20]`). Because `%s` does not stop at `"CTF"`, the trailing `"CTF"` in the format string is never reached unless preceded by whitespace.
3. **Comparisons (`0x11e2` – `0x1216`):**
   - Checks that `strcmp(buf, "__dso_handle") != 0`.
   - Checks that `strcmp(buf, "_init") == 0`.
   - If `buf` equals `"_init"`, prints `"Correct!"`.

Therefore, the input must be `"DoYouEven"` + `"_init"` = `DoYouEven_init`.

- **Password**: `DoYouEven_init`
- **Flag**: `THM{DoYouEven_init}`
