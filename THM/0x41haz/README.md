# TryHackMe — 0x41haz (Complete Technical Write-Up)

- **Room**: [0x41haz](https://tryhackme.com/room/0x41haz)
- **Category**: Reverse Engineering / ELF Header Repair & `x86_64` Crackme
- **Artifacts in Repo**:
  - [`0x41haz-1640335532346.0x41haz`](./0x41haz-1640335532346.0x41haz) (`14,432` bytes, corrupted 64-bit ELF PIE executable)
  - [`0x41haz_fixed`](./0x41haz_fixed) (`14,432` bytes, repaired ELF executable)
  - [`solve.py`](./solve.py) (Automated ELF header patcher, stack password extractor, and verifier)

---

## 1. Initial Binary Triage & ELF Header Inspection

Running `file` and `xxd -l 64` on `0x41haz-1640335532346.0x41haz`:

### Command Executed
```bash
file 0x41haz-1640335532346.0x41haz && xxd -l 64 0x41haz-1640335532346.0x41haz
```

### Output
```text
0x41haz-1640335532346.0x41haz: ELF 64-bit MSB *unknown arch 0x3e00* (SYSV)
00000000: 7f45 4c46 0202 0100 0000 0000 0000 0000  .ELF............
00000010: 0300 3e00 0100 0000 8010 0000 0000 0000  ..>.............
00000020: 4000 0000 0000 0000 6031 0000 0000 0000  @.......`1......
00000030: 0000 0000 4000 3800 0b00 4000 1c00 1b00  ....@.8...@.....
```

### Root Cause of Corruption
Inspecting the ELF header fields at offset `0x10`:
- `e_type` = `03 00` (`0x0003` in Little-Endian = `ET_DYN` PIE executable)
- `e_machine` = `3e 00` (`0x003e` in Little-Endian = `EM_X86_64`)

All multi-byte fields in the ELF header are stored in **Little-Endian (`LSB`)** format, but byte offset `0x05` (`e_ident[EI_DATA]`) was tampered with and set to `0x02` (`ELFDATA2MSB`, Big-Endian) instead of `0x01` (`ELFDATA2LSB`, Little-Endian). Because of this, the OS loader and analysis tools read `3e 00` as big-endian `0x3e00` (`*unknown arch 0x3e00*`).

---

## 2. Repairing the ELF Header (`e_ident[EI_DATA]`)

Patching byte offset `0x05` from `0x02` to `0x01` restores a valid 64-bit x86-64 LSB PIE binary:

```bash
python3 -c '
data = bytearray(open("0x41haz-1640335532346.0x41haz", "rb").read())
data[5] = 1
open("0x41haz_fixed", "wb").write(data)
' && chmod +x 0x41haz_fixed && file 0x41haz_fixed
```

```text
0x41haz_fixed: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6c9f2e85b64d4f12b91136ffb8e4c038f1dc6dcd, for GNU/Linux 3.2.0, stripped
```

---

## 3. Disassembling `.text` & Extracting the Password

Since the binary is stripped, we inspect the entry point (`0x1080`), which passes `rdi = 0x1165` (`main`) to `__libc_start_main`:

```bash
objdump -d -M intel -j .text 0x41haz_fixed
```

```assembly
    1165: 55                            push   rbp
    1166: 48 89 e5                      mov    rbp,rsp
    1169: 48 83 ec 40                   sub    rsp,0x40
    116d: 48 b8 32 40 40 32 35 24 67 66 movabs rax,0x6667243532404032
    1177: 48 89 45 ea                   mov    QWORD PTR [rbp-0x16],rax
    117b: c7 45 f2 73 54 26 40          mov    DWORD PTR [rbp-0xe],0x40265473
    1182: 66 c7 45 f6 4c 00             mov    WORD PTR [rbp-0xa],0x4c
...
    11ac: 48 8d 45 c0                   lea    rax,[rbp-0x40]
    11b0: 48 89 c7                      mov    rdi,rax
    11b3: b8 00 00 00 00                mov    eax,0x0
    11b8: e8 93 fe ff ff                call   1050 <gets@plt>
    11bd: 48 8d 45 c0                   lea    rax,[rbp-0x40]
    11c1: 48 89 c7                      mov    rdi,rax
    11c4: e8 77 fe ff ff                call   1040 <strlen@plt>
    11c9: 89 45 f8                      mov    DWORD PTR [rbp-0x8],eax
    11cc: 83 7d f8 0d                   cmp    DWORD PTR [rbp-0x8],0xd
    11d0: 74 16                         je     11e8
```

### Reconstructing the Stack String (`[rbp-0x16]` .. `[rbp-0x09]`)
1. `[rbp-0x16]` (8 bytes, little-endian `0x6667243532404032`):
   `32 40 40 32 35 24 67 66` -> `"2@@25$gf"`
2. `[rbp-0x0e]` (4 bytes, little-endian `0x40265473`):
   `73 54 26 40` -> `"sT&@"`
3. `[rbp-0x0a]` (2 bytes, little-endian `0x004c`):
   `4c 00` -> `"L\x00"`

The function checks `strlen(input) == 13` (`0xd`) and compares each character of `input` (`[rbp-0x40]`) against the stack string (`[rbp-0x16]`):
- **Recovered Password**: `2@@25$gfsT&@L`
- **Flag**: `THM{2@@25$gfsT&@L}`
