# Novatek HDMA physical-memory mapping

> **Research note:** This file preserves implementation and reverse-engineering
> details. It is not an end-user setup guide. Everything below was measured on a
> single retail set; it is not a compatibility claim for other `T-KTSU2AKUC`
> builds, and it is not part of the shipped CLI.

## Target

| | |
|---|---|
| Model | `UN55TU7000DFXZA` (55" 7 Series, 2020) |
| Platform | `20_KANTSU2_UHD_BASIC`, Novatek `NT7268x` (`_nvtca9-16m` in the kernel command line) |
| OS | Tizen 5.5.0 (Tizen5/TV) |
| Firmware | `T-KTSU2AKUC-REL-202607021959` (version `2743.0`) |
| Kernel | Linux 4.1.10, `armv7l`, 32-bit userspace |
| Managed runtime | shared framework `3.0.0` only; **no** `/usr/bin/dotnet`, no `corerun`, no `hostfxr` |

A 2020 model still receiving firmware in July 2026. Every route in this
repository is keyed to an exact build, so the build date matters more than the
model year.

## Why this route exists

On this generation neither of the packaged routes applies:

- `archive-root` needs `/usr/bin/dotnet` to host its assembly. This set has an
  AUL apphost and a runtime directory, but no generic host binary.
- The `ntksys` physical-memory route is closed: `/dev/ntksys` has no `mmap`
  operation at all, so it answers `ENODEV` (`file->f_op->mmap == NULL`) while
  every error path in the published `_SYS_MMAP` returns `EINVAL`. Re-deriving
  the ioctl surface cannot reach it.
- Native executables are UEP-gated — see [UEP](#uep-is-path-gated) below — and
  a native app package installs but refuses to launch (`SF_STATUS_UEP_FILE_NOT_SIGNED`).

What is left is a device node that is reachable from `uid=901(sdk)` without any
capability, and a driver whose bounds check does not hold. The node belongs to
the audio DMA engine (platform device `sdp-dma.4`, module `ntkndpalsa`), but the
bug makes its buffer base an arbitrary physical address, so the engine's audio
role does not bound what can be mapped.

## Foothold and payload host

The initial foothold is the public `SVE-2025-50109` SDB package-name injection,
unchanged: `uid=901(sdk)`, SMACK label `System`, groups include
`system_share`, `input`, `display`, and the usual `priv_*` set. The injection
argument has to stay under roughly 510 bytes; longer commands fall back to
staging a script, which UEP then refuses.

The payload host is the part worth generalizing:

```sh
/usr/bin/dotnet-launcher --standalone /home/owner/share/tmp/sdk_tools/Payload.dll
```

This runs an arbitrary managed assembly as `uid=901` with **no package, no
signing, and no capability** — exactly the properties `archive-root` needs from
`/usr/bin/dotnet` and does not get on this set. The shared framework tops out at
`Microsoft.NETCore.App 3.0.0`, so the assembly targets `netcoreapp3.0`.

`/usr/bin/dotnet-launcher` is a signed AUL apphost, so `execve` on it is fine;
CoreCLR then maps the assembly as **data**, and UEP is never consulted. That is
the whole bypass: no unsigned executable is ever executed.

The payload process runs with an empty effective capability set (`CapEff=0`),
so anything requiring `cap_sys_admin` — the
bind-mount and `sdbd-tarlauncher` step of `archive-root` — is out of reach from
here. `/dev/ntkhdma` does not require a capability.

## The bug

The Novatek `nt72682` driver source is public. In `ker_hdma.c`, `_hdmaMmap`
computes its bounds in `u32`:

```c
u32 off      = pstVMA->vm_pgoff << PAGE_SHIFT;
u32 physAddr = gu32HDMAMemPhysAddr + off;
u32 virtSize = pstVMA->vm_end - pstVMA->vm_start;
u32 physSize = gu32HDMAMemSize - off;       /* 32 KB buffer */

if( gu32HDMAMemPhysAddr == 0 ) return -EINVAL;
if( virtSize > physSize )      return -EINVAL;

pstVMA->vm_page_prot = pgprot_noncached( pstVMA->vm_page_prot );
io_remap_pfn_range( pstVMA, pstVMA->vm_start, physAddr >> PAGE_SHIFT,
                    virtSize, pstVMA->vm_page_prot );
```

`gu32HDMAMemSize` is `1024 << 5` (32 KB), so for any `off` past 32 KB the
subtraction underflows and `physSize` becomes a huge unsigned value. The size
guard always passes, and `physAddr` — base plus a caller-chosen offset — is
handed to `io_remap_pfn_range`. The mmap offset is therefore a physical address.

`KER_HDMA_IO_GET_BUFF_ADDR` (`_IOR(90, 3, u32)`, `0x80045A03`) returns the base
to subtract.

The built `ntkdriver.ko` was not readable on the device, so this is the
published source's arithmetic, confirmed against behaviour rather than against
the binary. `/sys/module/ntkdriver/parameters/` is readable and consistent with
it (`g_XDMADbgMask=7`, `gu32NumOfBuffer=0`, `gu32SplitSize=307200`).

## Measured behaviour

One ioctl and five read-only maps, from a capability-less `uid=901` process:

```text
hdma: ioctl GET_BUFF_ADDR -> rc=0 errno=0 phys=0x81040000
hdma: mmap(off 0x00000000 -> phys 0x81040000) 0x00110001 0xfc0d0934 ...
hdma: mmap(off 0x80fc0000 -> phys 0x02000000) 0xd474e3c0 0x00000000 0xc0152548 ...
hdma: mmap(off 0x80fc8000 -> phys 0x02008000) 0xea000000 0xea00659f 0xe1a0c001 ...
hdma: mmap(off 0xbb7c0000 -> phys 0x3c800000) 0xed2c82bb 0xb2fcd086 ...
hdma: mmap(off 0xfefc0000 -> phys 0x80000000) 0x02020202 0x02020202 ...
```

`0xea000000` is an ARM branch instruction at `0x02008000`, the usual zImage
load address for this RAM layout. That is arbitrary physical read of kernel
memory, with no USB stick and no firmware image.

RAM windows come from `/proc/cmdline` (`mem=808M@32M mem=56M@968M
mem=256M@2048M`); `/proc/iomem` is zeroed. A read-only sweep runs at
~16 MB/s — 808 MB in 48.9 s on one boot, ~85 s on another.

## Credential patch

The scan looks for a task's credentials by pattern: a non-zero word followed by
eight consecutive `901` values (`uid`, `gid`, `suid`, `sgid`, `euid`, `egid`,
`fsuid`, `fsgid`). Candidates that do not make `getuid()` return `0` are
restored to the exact bytes that matched.

Writing has a wrinkle worth recording. `_hdmaMmap` sets `pgprot_noncached`, so a
store reaches DRAM but leaves any cached copy of the line intact: the first run
zeroed a candidate and `getuid()` became `0`, the next zeroed a candidate, read
`0` back through the mapping, and still returned `901`. The fix is to touch an
8 MB cacheable buffer after each write and re-read `getuid()`; a clean line is
evicted and the patch is visible, a dirty line writes its old contents back over
the zeros, which reads as "not ours" and gets restored.

```text
credpatch: SUCCESS at phys=0x17c26800 usage=80 getuid=0 child_root=False
```

The payload is reaped a minute or two after launch, and a timed-out run can
leave a zombie holding the node, so the patch has to run in the same process that
finds the candidate: collect-then-patch sweeps died mid scan at 70–103 s.
Patch-on-hit landed root in 45 s. The practical form is **root-and-act** — stage
a command file, and the process that lands the patch runs it immediately instead
of waiting to be reaped.

Consequences to state plainly:

- which object gets zeroed decides the blast radius. A hit on a shared `struct
  cred` (`usage` 78–80) hands `uid 0` to every process that references it. A hit
  on the credential the session spawner hands to new processes (`usage` 1; two
  addresses on one boot) makes later injections start as `uid 0` for the rest of
  the boot. That is the only "persistence" observed, and it is not deterministic:
  targeting the spawner credential by address is still open.
- nothing else survives. A reboot returns the set to stock.
- `uid 0` does **not** imply MAC override. The process keeps the `System` SMACK
  label it started with, and the capability bounding set is `0x300200040`, so
  `sys_admin`/`mac_admin` need a root-on-exec child.

## UEP is path gated

| Attempt | Result |
|---|---|
| copy of the signed `/usr/bin/base64` into `/tmp` | `Operation not permitted` |
| the same copy into the sdb staging directory | `Operation not permitted` |
| static armv7 binary (zig `-target arm-linux-musleabihf`) | `Operation not permitted` |
| `/lib/ld-linux.so.3 /tmp/b64` (signed loader as bypass) | `failed to map segment from shared object` |

A byte-identical copy of a signed system binary still fails, so the gate is the
path, not the content, and the loader is not a way around it. Passing a script
as content rather than as a file works, because `/bin/sh` is what gets executed:
`sh -c "$(cat /path/script.sh)"`.

A native `capp` package installs (`key[end] val[ok]`) and then refuses to launch
with `SF_STATUS_UEP_FILE_NOT_SIGNED`; re-signing the package does not sign the
embedded ELF, so that route needs per-binary signing tooling. Managed code is
the only execution primitive this generation offers.

## Minimal read-only check for another owner

Before any write, an owner of a sibling `T-KTSU2AKUC` or `T-NKMAKUC` build can
answer the two questions that matter without touching memory:

1. `ls -l /dev/ntkhdma` from the injection shell — is the node present and
   reachable as `uid 901`?
2. open it, call `GET_BUFF_ADDR`, then `mmap` **one page** with `PROT_READ` at
   the offset that should land on a known physical region:

   ```text
   off = (target_phys - base) mod 2**32
   ```

   With `base = 0x81040000`, targeting the first RAM window at `0x02000000`
   means `off = 0x80fc0000`. If the map succeeds and the bytes at
   `0x02008000` look like ARM branch code (`0xea…` on this build) rather than
   the 32 KB buffer's MMIO pointers, the wrap is present.

Anything past that is a write primitive on a TV in use. Mapping is read-only
until a candidate credential object has been validated.

## Status

`uid 0` was reached on one build on 2026-10-26: twice in a row on a healthy
channel that night, after a 2-in-7 the night before in which most failures were
the SDB channel rather than the scan. It is not reliable — the sweep is
non-deterministic, and carrying `uid 0` into the *next* launch is behavioural
rather than designed. It is not packaged, not persistent, and not a release
feature. No firmware, binary, or key is included here, in keeping with the rest
of this repository.
