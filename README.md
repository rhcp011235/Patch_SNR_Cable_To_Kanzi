# SNR Cable Firmware Patcher

Patches a Nova/SNR cable firmware dump to change its USB Product ID from `0x1624`
to `0x1621`, causing it to enumerate as a Kanzi debug probe instead of a retail
technician cable. Once flashed, the cable is recognized by Astris and can be used
as an SWD debug probe.

Based on the research documented at:
https://nyansatan.github.io/snr-udt-fw-patching/

---

## Background

Apple produces several USB-based debug and diagnostic cables for internal use:

| Cable   | Connector  | USB PID | Purpose                        |
|---------|------------|---------|--------------------------------|
| Kanzi   | Lightning  | 0x1621  | SWD debug probe                |
| Nova    | Lightning  | 0x1624  | Retail technician variant      |
| SNR     | Lightning  | 0x1624  | Serial Number Reader (retail)  |
| Chimp   | USB-C      | 0x162C  | SWD debug probe                |
| UDT     | USB-C      | 0x168C  | USB-C Diagnostic Tool (retail) |

All of these share the same Apple Vendor ID (`0x05AC`). The Kanzi and Nova/SNR are
hardware-identical or nearly so. The only functional difference that prevents the
SNR from working as a debug probe is the USB Product ID it reports. Astris, Apple's
internal probe server daemon (`astrisprobed`), filters on PID and will not attach to
a `0x1624` device.

The firmware is stored on an STM32F407 microcontroller (ARM Cortex-M4). The bootloader
is called KanziBoot. When the cable enumerates over USB, the firmware sets the PID
value into a USB descriptor structure at runtime. This patcher finds that assignment
and changes the PID byte from `0x24` to `0x21`, then recalculates the CRC so the
bootloader accepts the image.

---

## Hardware

The SNR cable contains:

- **MCU**: STM32F407 (ARM Cortex-M4, Thumb-2 instruction set)
- **Flash**: 1 MB, mapped at `0x08000000` in the STM32 memory map
- **Button**: Inside the enclosure, accessible through the LED hole using a SIM
  ejector tool or a needle. Used to force bootloader mode.
- **LED**: Green in normal operation, orange in bootloader mode.

The full flash dump is a 1,048,576-byte (1 MB) file. Most of it past the firmware
end is blank flash (`0xFF`).

---

## Firmware Layout

```
File offset    STM32 address    Contents
-----------    -------------    --------
0x00000        0x08000000       KanziBoot bootloader (16 KB)
0x04000        0x08004000       Main firmware (begins here)
0x04000+0x1C   0x0800401C       Firmware length field (LE uint32)
fw_end-4                        STM32 CRC32 checksum (LE uint32)
fw_end+                         Blank flash (0xFF padding)
```

The firmware length field at `fw+0x1C` gives the total size of the firmware image
in bytes, including the 4-byte CRC at the end. For the firmware this patcher targets,
the value is `0xD19C` (53,660 bytes), placing the firmware from `0x4000` to `0x1119C`
in the file.

---

## The Patch

### What gets changed

One byte, at file offset `0x0426C`, STM32 address `0x0800426C`:

```
Before:  24 21   (MOVEQ R1, #0x24)
After:   21 21   (MOVEQ R1, #0x21)
```

### Why this works

The USB descriptor is written in this code sequence:

```
0x08004264    21 21         movs  r1, #0x21       ; default PID low byte (Kanzi)
0x08004266    04 28         cmp   r0, #4           ; is board revision == 4?
0x08004268    82 48         ldr   r0, [pc, #0x208] ; load USB descriptor pointer
0x0800426a    08 bf         it eq                  ; if board revision == 4...
0x0800426c    24 21         moveq r1, #0x24        ; ...override with SNR PID low byte
0x0800426e    81 72         strb  r1, [r0, #0xa]   ; write PID low byte to descriptor
0x08004270    16 21         movs  r1, #0x16        ; VID high byte (0x05AC -> 0x16)
0x08004272    c1 72         strb  r1, [r0, #0xb]   ; write VID high byte to descriptor
```

The firmware starts with `R1 = 0x21` (the Kanzi PID byte). It then checks the board
revision value in `R0`. If the board revision is 4 (which is the case on SNR hardware),
the `IT EQ` / `MOVEQ` pair conditionally overrides `R1` to `0x24` before writing it
into the USB descriptor.

Changing `0x24` to `0x21` in the `MOVEQ` instruction means the override still
executes on revision-4 hardware, but it writes `0x21` instead. The result is that
the cable always sets PID low byte to `0x21` regardless of board revision, making
the full PID `0x1621` (Kanzi).

The VID bytes (`0x05AC`) are not touched.

### Why only 1 byte changes

The Thumb-2 encoding of `MOVS Rn, #imm8` is a 16-bit instruction:

```
Encoding: imm8 | (Rn << 8)
```

For `MOVS R1, #0x24`: `0x24 | (1 << 8)` = `0x2124`, little-endian: `24 21`
For `MOVS R1, #0x21`: `0x21 | (1 << 8)` = `0x2121`, little-endian: `21 21`

The register field and the high byte are the same in both. Only the immediate value
byte changes, which is the byte at the lower address. The result is a single byte
change from `0x24` to `0x21`.

---

## CRC Algorithm

The STM32F407 has a hardware CRC unit. KanziBoot uses it to validate the firmware
image before jumping to it. If the CRC check fails, the bootloader stays in upgrade
mode rather than booting the firmware. This is the recovery mechanism — a bad flash
does not permanently brick the cable because the bootloader itself is in a separate
protected region.

The algorithm is the STM32 hardware CRC32:

- Polynomial: `0x04C11DB7`
- Initial value: `0xFFFFFFFF`
- Input processing: little-endian 32-bit words (not reflected)
- No output XOR
- No input/output bit reflection

This is distinct from the standard zlib/Ethernet CRC32 (`0xEDB88320`, which uses
the bit-reflected polynomial). The STM32 unit processes each 32-bit word MSB-first
after reading it from memory in little-endian byte order.

The stored CRC at `fw_end-4` is chosen such that:

```
stm32_crc32(firmware[0 : fw_len-4]) == stored_crc
stm32_crc32(firmware[0 : fw_len])   == 0x00000000
```

The full-firmware check equaling zero is a residue property of this specific CRC
configuration. The patcher verifies both conditions after writing the new CRC.

Known test vector for verification: `stm32_crc32(0x12345678 as LE uint32)` = `0xDF8A8A2B`.

---

## Requirements

- Python 3.9 or later
- `capstone` Python package (required only for `--check`; not needed for patching)

```
pip install capstone
```

---

## Usage

### Patch a firmware dump

```
python3 snr_patch.py [input] [output]
```

| Argument | Default               | Description                  |
|----------|-----------------------|------------------------------|
| input    | `snr_cable.bin`       | Raw firmware dump (1 MB)     |
| output   | `snr_cable_patched.bin` | Destination for patched image |

The script will:

1. Read the firmware length from `fw+0x1C`.
2. Verify the original CRC is valid. If it is not, it exits without making changes.
3. Search for the 2-byte-aligned occurrence of `24 21` in the firmware region.
4. Replace it with `21 21`.
5. Recompute the STM32 CRC32 over the patched firmware body.
6. Write the new CRC into the last 4 bytes of the firmware.
7. Verify that `stm32_crc32(full_patched_firmware) == 0`.
8. Write the output file.

A backup of the input file is saved to `input.bak` automatically on the first run.

Example:

```
$ python3 snr_patch.py snr_cable.bin snr_cable_patched.bin
Backup saved to snr_cable.bin.bak
Firmware: offset=0x4000, length=0xd19c, CRC at 0x11198
Original CRC: 0xbd5980e0
CRC verified OK
Found 1 aligned occurrence(s) of 24 21
Patched @ file 0x0426c:
  before: 82 48 08 bf 24 21 81 72 16 21 c1 72
  after:  82 48 08 bf 21 21 81 72 16 21 c1 72
New CRC: 0x23befadb
New CRC verified OK (full check = 0x00000000)
Written to: snr_cable_patched.bin
```

### Inspect the patch site

```
python3 snr_patch.py --check [input]
```

Reads the file without modifying it. Prints:

- Firmware region boundaries and size
- CRC status (stored value, computed value, pass/fail)
- Whether the binary is in an unpatched or patched state
- Disassembly of the code surrounding the patch site, with the target instruction
  marked with `>>`
- A simulated before/after view so the effect of the change is visible

Works on both the original dump and an already-patched output file. When run on an
unpatched file it shows the current state and a simulated post-patch view. When run
on an already-patched file it shows the current state and a reconstructed pre-patch
view.

Example output (unpatched):

```
File:     snr_cable.bin
Firmware: 0x4000-0x1119c  (53660 bytes)
CRC:      stored=0xbd5980e0  computed=0xbd5980e0  OK
          full-check (should be 0): 0x00000000  OK
State:    UNPATCHED

Patch site @ fw+0x026c  (file 0x0426c,  STM32 0x0800426c)
  Change: 24 21 (MOVS R1, #0x24 -> PID 0x1624 (SNR))  ->  21 21 (MOVS R1, #0x21 -> PID 0x1621 (Kanzi/debug))

  -- Current (unpatched) --
     0x08004260  b9 f8 c0 b2   ldrh.w fp, [sb, #0x2c0]
     0x08004264  21 21         movs r1, #0x21
     0x08004266  04 28         cmp r0, #4
     0x08004268  82 48         ldr r0, [pc, #0x208]
     0x0800426a  08 bf         it eq
  >> 0x0800426c  24 21         moveq r1, #0x24
     0x0800426e  81 72         strb r1, [r0, #0xa]
     0x08004270  16 21         movs r1, #0x16
     0x08004272  c1 72         strb r1, [r0, #0xb]

  -- After patch --
     0x08004260  b9 f8 c0 b2   ldrh.w fp, [sb, #0x2c0]
     0x08004264  21 21         movs r1, #0x21
     0x08004266  04 28         cmp r0, #4
     0x08004268  82 48         ldr r0, [pc, #0x208]
     0x0800426a  08 bf         it eq
  >> 0x0800426c  21 21         moveq r1, #0x21
     0x0800426e  81 72         strb r1, [r0, #0xa]
     0x08004270  16 21         movs r1, #0x16
     0x08004272  c1 72         strb r1, [r0, #0xb]
```

---

## Patch Detection

The `--check` mode and the patcher both identify the patch site using a 4-byte
signature rather than a bare 2-byte search:

```
Unpatched signature:  08 BF 24 21   (IT EQ + MOVEQ R1, #0x24)
Patched signature:    08 BF 21 21   (IT EQ + MOVEQ R1, #0x21)
```

The reason for including the preceding `IT EQ` instruction (`08 BF`) in the
signature is that the byte sequence `21 21` (`MOVS R1, #0x21`) appears elsewhere
in the firmware as unrelated code. Using the 2-byte target alone would produce
false positives. The `IT EQ` prefix is unique to this location in context because
the unconditional `MOVS R1, #0x21` at `0x08004264` is not preceded by an IT
instruction.

---

## Flashing the Patched Firmware

Flashing requires putting the cable into bootloader mode and then writing the image
using `kblctl` from the kanzitools project:

https://github.com/NyanSatan/kanzitools

### Step 1: Obtain the firmware dump

Use `kblctl` to read the current firmware from the cable before patching:

```
kblctl dump snr_cable.bin
```

### Step 2: Patch

```
python3 snr_patch.py snr_cable.bin snr_cable_patched.bin
```

Verify with `--check` before proceeding:

```
python3 snr_patch.py --check snr_cable_patched.bin
```

Confirm the output shows `State: PATCHED` and `CRC: OK`.

### Step 3: Enter bootloader mode

With the cable connected to a Mac:

1. Locate the small hole in the LED end of the cable housing.
2. Insert a SIM ejector tool or a thin needle and press gently. There is a button
   inside. You will feel it click.
3. Watch the LED. It will change from green to orange. Orange means the cable is
   in bootloader (DFU) mode.
4. Release.

If you miss the transition or the LED goes back to green, unplug, replug, and try
again. The button does not need to be held.

### Step 4: Flash

```
kblctl flash snr_cable_patched.bin
```

Or, if using `astrisctl`:

```
astrisctl flash snr_cable_patched.bin
```

The LED will flash during the write and return to solid green when done.

### Step 5: Verify

Unplug and replug the cable. Check the USB PID:

```
system_profiler SPUSBDataType | grep -A5 "Apple"
```

The cable should now report PID `0x1621`. Astris should recognize it as a Kanzi
probe.

---

## Recovery

KanziBoot is stored in the first 16 KB of flash (`0x0000-0x3FFF`) and is separate
from the main firmware region. The patcher does not touch this region. Even if the
main firmware is completely corrupted, the bootloader survives and the cable will
stay in bootloader mode on the next power cycle, allowing a fresh image to be
flashed.

If the cable is ever in a state where it will not enumerate normally:

1. Plug it in.
2. Press the button through the LED hole immediately after plugging in, or hold it
   during plug-in.
3. The LED should come up orange (bootloader mode).
4. Flash a known-good image.

The backup created by the patcher (`snr_cable.bin.bak`) is the unmodified original
dump. Keep it. If the patched firmware has any problem, flash the original back.

---

## What the Patcher Does Not Do

- It does not patch `astrisprobed`. The host-side daemon also checks PIDs. If
  `astrisprobed` on your Mac does not already support `0x1621`, you will need to
  patch it separately (see the linked research page for methods).
- It does not modify the bootloader region.
- It does not change any bytes outside the firmware region and its CRC field.
- It does not support UDT cables. The UDT patch is different and more involved
  (the UDT firmware actively rejects non-UDT operation; see the linked research
  page).

---

## Verified Results

The following was confirmed on the firmware dump this patcher targets:

| Check                                              | Result |
|----------------------------------------------------|--------|
| Bootloader region unchanged                        | Pass   |
| Post-firmware padding unchanged                    | Pass   |
| Exactly 1 byte changed in firmware body            | Pass   |
| STM32 CRC32 test vector (0x12345678 -> 0xDF8A8A2B) | Pass   |
| Original CRC valid before patch                    | Pass   |
| Patched CRC valid after patch                      | Pass   |
| IT EQ instruction precedes patch site              | Pass   |
| STRB (USB descriptor write) follows patch site     | Pass   |
| VID high byte (0x16) unchanged                     | Pass   |
| CMP R0, #4 (board revision check) present          | Pass   |
| No residual SNR PID bytes in patched firmware      | Pass   |
| File size unchanged                                | Pass   |

Patched binary SHA256 of the modified region (`0x4260-0x4280`):

```
d552990050ad82a27124f0a8f82659b8c81ae51986903acbe24dc38f156219fe
```

---

## Reference

- Research and original patch discovery:
  https://nyansatan.github.io/snr-udt-fw-patching/
- kanzitools (kblctl, kblcrcfix, probeenterdfu):
  https://github.com/NyanSatan/kanzitools
- STM32F407 CRC unit reference:
  STM32F4 Reference Manual (RM0090), section 4.3 (CRC calculation unit)
- STM32 CRC test vectors:
  ST Application Note AN4187
