#!/usr/bin/env python3
"""
SNR Cable Firmware Patcher
Patches snr_cable.bin to change USB PID from 0x1624 (Nova/SNR) to 0x1621 (Kanzi)
so the cable is recognized by Astris as a debug probe.

Based on: https://nyansatan.github.io/snr-udt-fw-patching/
Firmware structure:
  0x0000-0x3FFF  : KanziBoot bootloader
  0x4000+        : Main firmware
  fw+0x1C        : Firmware length (LE uint32)
  fw[len-4:len]  : CRC32 checksum (STM32 hardware CRC, poly 0x04C11DB7)

Patch: MOVS R1, #0x24 → MOVS R1, #0x21
       Thumb2: 24 21 → 21 21
"""

import argparse
import struct
import sys
import os
import shutil

BEFORE = bytes([0x24, 0x21])   # MOVS R1, #0x24  (PID low byte = 0x24 → full PID 0x1624)
AFTER  = bytes([0x21, 0x21])   # MOVS R1, #0x21  (PID low byte = 0x21 → full PID 0x1621)

# Unique 4-byte signatures including the preceding IT EQ instruction (0x08 0xBF),
# which makes the match unambiguous even though 21 21 appears naturally elsewhere.
SIG_BEFORE = bytes([0x08, 0xBF, 0x24, 0x21])   # IT EQ + MOVEQ R1, #0x24 (unpatched)
SIG_AFTER  = bytes([0x08, 0xBF, 0x21, 0x21])   # IT EQ + MOVEQ R1, #0x21 (patched)

FW_START = 0x4000
FW_LEN_OFFSET = 0x1C          # relative to FW_START


def stm32_crc32(data: bytes) -> int:
    """
    STM32 hardware CRC32 unit algorithm.
    Polynomial: 0x04C11DB7, Init: 0xFFFFFFFF, no reflection.
    Processes data as little-endian 32-bit words.
    CRC32(body) == stored last 4 bytes, and CRC32(body + stored) == 0.
    """
    crc = 0xFFFFFFFF
    for i in range(0, len(data), 4):
        word = struct.unpack_from('<I', data, i)[0]
        crc ^= word
        for _ in range(32):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
    return crc


def disassemble_region(data: bytes, file_offset: int, length: int, mark_offset: int, mark_len: int) -> None:
    """
    Disassemble `length` bytes at `file_offset` in `data` using Capstone (ARM Thumb-2).
    Marks the instruction(s) at `mark_offset` (file offset) with a '>>' indicator.
    The STM32F407 flash alias maps file offsets to 0x08000000+offset.
    """
    try:
        import capstone
    except ImportError:
        print("  [capstone not installed — pip install capstone]")
        return

    cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB | capstone.CS_MODE_LITTLE_ENDIAN)
    cs.detail = False

    chunk = data[file_offset:file_offset + length]
    base_addr = 0x08000000 + file_offset   # STM32F4 flash alias

    mark_end = mark_offset + mark_len

    for insn in cs.disasm(chunk, base_addr):
        rel = insn.address - (0x08000000 + file_offset) + file_offset  # back to file offset
        in_patch = (file_offset <= rel < file_offset + length and
                    mark_offset <= rel < mark_end)
        marker = ">>" if in_patch else "  "
        print(f"  {marker} 0x{insn.address:08x}  {insn.bytes.hex(' '):<12}  {insn.mnemonic} {insn.op_str}")


def check(input_path: str) -> None:
    """
    Locate the patch site and print a before/after disassembly view.
    Works on both the original and already-patched binary.
    """
    with open(input_path, 'rb') as f:
        data = f.read()

    fw_len = struct.unpack_from('<I', data, FW_START + FW_LEN_OFFSET)[0]
    fw_end = FW_START + fw_len
    firmware = data[FW_START:fw_end]

    # Check CRC state
    stored_crc = struct.unpack_from('<I', data, fw_end - 4)[0]
    computed_crc = stm32_crc32(firmware[:-4])
    crc_ok = computed_crc == stored_crc
    crc_full = stm32_crc32(firmware)

    print(f"File:     {input_path}")
    print(f"Firmware: 0x{FW_START:04x}–0x{fw_end:04x}  ({fw_len} bytes)")
    print(f"CRC:      stored=0x{stored_crc:08x}  computed=0x{computed_crc:08x}  {'OK' if crc_ok else 'MISMATCH'}")
    print(f"          full-check (should be 0): 0x{crc_full:08x}  {'OK' if crc_full == 0 else 'FAIL'}")

    # Find patch targets using the 4-byte signature (IT EQ + instruction) to avoid
    # false positives from naturally-occurring 21 21 / 24 21 bytes elsewhere.
    def find_sig(sig: bytes) -> list[int]:
        """Return fw-relative offsets where sig occurs at an even (2-byte aligned) boundary."""
        results = []
        offset = 0
        while True:
            idx = firmware.find(sig, offset)
            if idx == -1:
                break
            # The instruction itself starts 2 bytes in; check that boundary is even
            if (idx + 2) % 2 == 0:
                results.append(idx + 2)   # point at the instruction, not the IT prefix
            offset = idx + 1
        return results

    targets_before = find_sig(SIG_BEFORE)
    targets_after  = find_sig(SIG_AFTER)

    # Determine state
    if targets_before and not targets_after:
        state = "UNPATCHED"
        targets = targets_before
        patch_bytes = BEFORE
    elif targets_after and not targets_before:
        state = "PATCHED"
        targets = targets_after
        patch_bytes = AFTER
    elif targets_before and targets_after:
        state = "MIXED (unexpected — both signatures present)"
        targets = targets_before + targets_after
        patch_bytes = BEFORE
    else:
        print("\nERROR: Patch target not found (neither IT EQ + 0x24 nor IT EQ + 0x21).")
        sys.exit(1)

    print(f"State:    {state}")
    print()

    CONTEXT_BEFORE = 12   # bytes of code to show before patch site
    CONTEXT_AFTER  = 16   # bytes of code to show after patch site

    for fw_rel in targets:
        file_off = FW_START + fw_rel
        region_start = max(FW_START, file_off - CONTEXT_BEFORE) & ~1  # align to 2
        region_len   = (file_off - region_start) + len(patch_bytes) + CONTEXT_AFTER

        print(f"Patch site @ fw+0x{fw_rel:04x}  (file 0x{file_off:05x},  STM32 0x{0x08000000+file_off:08x})")
        print(f"  Change: {BEFORE.hex(' ')} ({_bytes_label(BEFORE)})  →  "
              f"{AFTER.hex(' ')} ({_bytes_label(AFTER)})")
        print()

        if state == "UNPATCHED":
            # Show current (unpatched) disassembly
            print("  -- Current (unpatched) --")
            disassemble_region(data, region_start, region_len, file_off, len(BEFORE))
            print()
            # Show simulated patched disassembly
            patched = bytearray(data)
            patched[file_off:file_off + len(BEFORE)] = AFTER
            print("  -- After patch --")
            disassemble_region(bytes(patched), region_start, region_len, file_off, len(AFTER))
        else:
            # Already patched — show current (patched) state
            print("  -- Current (patched) --")
            disassemble_region(data, region_start, region_len, file_off, len(AFTER))
            print()
            # Show what the original looked like
            original = bytearray(data)
            original[file_off:file_off + len(AFTER)] = BEFORE
            print("  -- Original (pre-patch) --")
            disassemble_region(bytes(original), region_start, region_len, file_off, len(BEFORE))


def _bytes_label(b: bytes) -> str:
    """Return a human-readable label for a known byte pattern."""
    if b == BEFORE:
        return "MOVS R1, #0x24  → PID 0x1624 (SNR)"
    if b == AFTER:
        return "MOVS R1, #0x21  → PID 0x1621 (Kanzi/debug)"
    return b.hex(' ')


def find_patch_targets(fw_data: bytes) -> list[int]:
    """
    Find all 2-byte-aligned occurrences of BEFORE in the firmware body.
    Skips the first 0x10 bytes (vector table area, not real code).
    """
    targets = []
    offset = 0
    while True:
        idx = fw_data.find(BEFORE, offset)
        if idx == -1:
            break
        if idx % 2 == 0:
            targets.append(idx)
        offset = idx + 1
    return targets


def patch(input_path: str, output_path: str) -> None:
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())

    fw_len = struct.unpack_from('<I', data, FW_START + FW_LEN_OFFSET)[0]
    fw_end = FW_START + fw_len
    crc_offset = fw_end - 4

    print(f"Firmware: offset=0x{FW_START:04x}, length=0x{fw_len:04x}, CRC at 0x{crc_offset:04x}")

    firmware_body = bytes(data[FW_START:fw_end])
    original_crc = struct.unpack_from('<I', data, crc_offset)[0]
    print(f"Original CRC: 0x{original_crc:08x}")

    # Verify original CRC is valid
    computed = stm32_crc32(firmware_body[:-4])
    if computed != original_crc:
        print(f"WARNING: CRC mismatch before patching! computed=0x{computed:08x}, stored=0x{original_crc:08x}")
        sys.exit(1)
    print("CRC verified OK")

    # Find patch location(s) within firmware region
    fw_region = firmware_body
    targets = find_patch_targets(fw_region)

    aligned_targets = [t for t in targets if t % 2 == 0]
    print(f"Found {len(aligned_targets)} aligned occurrence(s) of {BEFORE.hex(' ')}")

    if not aligned_targets:
        print("ERROR: Patch target not found in firmware!")
        sys.exit(1)

    if len(aligned_targets) > 1:
        print("Multiple matches found:")
        for t in aligned_targets:
            ctx = fw_region[max(0,t-4):t+8].hex(' ')
            print(f"  fw+0x{t:04x} (file 0x{FW_START+t:05x}): ...{ctx}...")
        # For the SNR patch, we want the one that follows an IT EQ / condition code
        # The correct one is typically preceded by a conditional IT instruction
        # Default: patch all (usually only 1 real match anyway)

    patched_count = 0
    for t in aligned_targets:
        file_offset = FW_START + t
        ctx_before = bytes(data[max(0,file_offset-4):file_offset+8]).hex(' ')
        data[file_offset:file_offset+2] = AFTER
        ctx_after = bytes(data[max(0,file_offset-4):file_offset+8]).hex(' ')
        print(f"Patched @ file 0x{file_offset:05x}:")
        print(f"  before: {ctx_before}")
        print(f"  after:  {ctx_after}")
        patched_count += 1

    if patched_count == 0:
        print("ERROR: No patches applied!")
        sys.exit(1)

    # Recompute CRC over patched firmware body (everything except last 4 bytes)
    new_fw_body = bytes(data[FW_START:fw_end - 4])
    new_crc = stm32_crc32(new_fw_body)
    struct.pack_into('<I', data, crc_offset, new_crc)
    print(f"New CRC: 0x{new_crc:08x}")

    # Verify new CRC
    verify = stm32_crc32(bytes(data[FW_START:fw_end]))
    assert verify == 0, f"CRC verification failed! got 0x{verify:08x}"
    print("New CRC verified OK (full check = 0x00000000)")

    # Write only bootloader + firmware (truncate 0xFF padding).
    # kblcrcfix does the same: it writes exactly BL_LEN + fw_len bytes.
    # kblctl sends whatever file size it receives; sending the full 1MB dump
    # causes a USB timeout because the bootloader stops reading after fw_end.
    with open(output_path, 'wb') as f:
        f.write(data[:fw_end])
    print(f"Written to: {output_path}  ({fw_end} bytes, padding stripped)")


def main():
    parser = argparse.ArgumentParser(
        description="SNR cable firmware patcher — changes USB PID 0x1624→0x1621 so Astris sees it as a Kanzi probe"
    )
    parser.add_argument("input", nargs="?", default="snr_cable.bin",
                        help="Input firmware binary (default: snr_cable.bin)")
    parser.add_argument("output", nargs="?", default="snr_cable_patched.bin",
                        help="Output path for patched binary (default: snr_cable_patched.bin)")
    parser.add_argument("--check", action="store_true",
                        help="Show disassembly of the patch site without modifying anything")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"ERROR: {args.input} not found")
        sys.exit(1)

    if args.check:
        check(args.input)
        return

    # Backup
    backup = args.input + ".bak"
    if not os.path.exists(backup):
        shutil.copy2(args.input, backup)
        print(f"Backup saved to {backup}")

    patch(args.input, args.output)


if __name__ == "__main__":
    main()
