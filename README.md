# alice_jst_patcher

A small Python tool that patches Alicesoft (System4 / NSystem) game executables to force the C runtime's timezone to Japan (UTC+9, no DST) regardless of your system timezone. Removes the "must set Windows clock to Japan time" requirement that crashes some titles outside JST.

## Why this exists

Several Alicesoft games crash on launch unless your Windows clock is in JST. The engine's script VM reads the current local time and feeds it to game logic that silently assumes it's running in Japan. Wrong timezone leads to wrong local time leads to a script that indexes off the end of an array or compares a date that no longer makes sense.

The fix is to short-circuit the C runtime's timezone setup so every call to `localtime` inside the game's process behaves as JST. Two patches, 21 bytes total. This tool does it automatically.

A longer write-up of why this happens and how the patch works is at [<https://dredsen.github.io/?p=alicesoft-jst-timezone-fix>](https://dredsen.github.io/post.html?p=alicesoft-jst-timezone-fix).

## Requirements

- Python 3.8 or newer
- A 32-bit Alicesoft game executable built with a statically-linked MSVC CRT (most modern titles)

## Usage

```
python alice_jst_patcher.py game.exe
```

The tool:

- Scans the EXE for the CRT timezone-setup function
- Applies the two patches
- Writes a `.bak` next to the original
- Tells you what it did

Other useful flags:

```
python alice_jst_patcher.py --dry-run game.exe     # preview, don't write
python alice_jst_patcher.py --restore game.exe     # revert from most recent .bak
python alice_jst_patcher.py --verbose game.exe     # show scan details
python alice_jst_patcher.py --force game.exe       # re-apply even if already patched
```

Re-running on an already-patched file is a no-op by default - the tool recognises its own work.

## What if the signature scan fails?

If you get `no patch location found`, the tool's signature didn't match. This usually means one of:

- The game is 64-bit (the CRT layout is different on x64; this tool is 32-bit only)
- The game uses a different MSVC CRT version with slightly different codegen
- The game dynamically links `msvcr*.dll` instead of statically linking the CRT (the function isn't in the EXE at all)

In the first and third case you're stuck without doing a lot more working yourself. In the second case you can find the patch site manually and patch the bytes yourself. Here's how.

## Finding the offsets yourself

You're looking for the CRT function `tzset_from_system_nolock`. It calls `GetTimeZoneInformation`, then computes the `_timezone` global from `TIME_ZONE_INFORMATION.Bias`.

### Step 1 - open the EXE in a disassembler

Any disassembler works. IDA (Free or Pro), Ghidra, Binary Ninja, or x64dbg in static mode are all fine. Steps below are written for IDA but translate one-to-one.

### Step 2 - find the function

1. Open the **Imports** view.
2. Find `GetTimeZoneInformation`.
3. Press `X` on it to list cross-references.
4. Jump to the call site - that's inside `tzset_from_system_nolock`.

The function is short. Scroll down from the `call GetTimeZoneInformation` instruction. Within ten or twenty instructions you'll see the conversion of `TimeZoneInformation.Bias` from minutes to seconds, which looks like:

```asm
imul    ecx, dword_XXXXXX, 3Ch     ; 3Ch = 60
```

The address is whatever the `TIME_ZONE_INFORMATION.Bias` field lives at in your binary.

### Step 3 - identify the two patch sites

A few instructions below the `imul`, you'll find:

```asm
mov     [ebp-4], ecx               ; <-- PATCH 1 starts here
cmp     [StandardDate.wMonth], bx
jz      short loc_skip
imul    eax, edx, 3Ch
add     ecx, eax
mov     [ebp-4], ecx               ; <-- PATCH 1 ends here (20 bytes total)
cmp     [DaylightDate.wMonth], bx
jz      short loc_dst              ; <-- PATCH 2 (this jz)
```

Note the file offset (not the runtime address) of the first `mov [ebp-4], ecx`. That's where Patch 1 starts. Note the file offset of the `jz` that follows the DaylightDate compare. That's Patch 2.

In IDA you can convert a virtual address to a file offset via **Edit → Segments → Rebase program** (to confirm image base) and the standard PE math: `file_offset = VA - image_base - section.RVA + section.raw_offset`. Or just use the **Hex View** alongside the disassembly - it shows the file offset of the cursor in the bottom-left status bar.

### Step 4 - write the patches

**Patch 1** - replace 20 bytes starting at the first `mov [ebp-4], ecx`:

| Offset (from patch start) | Original | New |
|---|---|---|
| 0..2  | `89 4D FC` | `C7 45 FC` |
| 3..6  | (cmp opcode bytes) | `70 81 FF FF` |
| 7..19 | (remaining bytes) | `90 90 90 90 90 90 90 90 90 90 90 90 90` |

In other words, replace the entire 20-byte window with:

```
C7 45 FC 70 81 FF FF 90 90 90 90 90 90 90 90 90 90 90 90 90
```

That's `mov dword ptr [ebp-4], -32400` (the JST offset in seconds, as a signed 32-bit little-endian int) followed by 13 NOPs to keep the function the same size.

**Patch 2** - one byte at the `jz short` that follows the DaylightDate compare:

| Original | New |
|---|---|
| `74` | `EB` |

`74` is the opcode for `jz short`. `EB` is the opcode for `jmp short`. Same operand size, so the second byte (the jump distance) stays untouched. After the patch, control always takes the "no DST" branch, which sets `_daylight = 0` and `_dstbias = 0`. Japan doesn't observe DST so this is correct.

### Step 5 - save and test

Save the patched EXE under a different name first so you can compare. Run the game. If it launches and runs normally on a non-JST timezone, you're done.

If you can't find the function or aren't confident about the bytes, open the script in this repo, look at the `ANCHOR_SIG` and `PATCH1_NEW` / `PATCH2_NEW` constants, and double-check your reading against those. The constants are heavily commented and explain exactly what each byte means.
