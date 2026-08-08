# captioncast

Rust 2024 port of `caption_poc.py`, built to run **on the RV6699 router** instead
of a PC. Unauthenticated DLNA media + caption injection against the owner's own
Samsung UE43NU7470. Own equipment only.

Single binary, **zero dependencies** (std only) — that keeps the cross-build to
"a toolchain and nothing else" and the binary small enough for the router.

## Why it does the odd things it does

Every quirk below came out of reversing the TV's own firmware
(`libDlnaReaderCore.so`, `libgstDlnaPlugin.so`) and from packet captures:

| Behaviour | Reason |
|---|---|
| `Server: … DLNADOC/1.50 …` | Samsung gates behaviour on that token |
| `Connection: close` + `shutdown()` after every body | miniDLNA closes each media socket unconditionally |
| `EXT:` and `realTimeInfo.dlna.org` | part of miniDLNA's mandatory header block |
| answers `MediaInfo.sec` / `CaptionInfo.sec` | the TV asks for them via `getMediaInfo.sec` / `getCaptionInfo.sec` |
| open-ended `Range: bytes=N-` served **to EOF** | capping it to a window → `ERROR_OCCURRED` in ~2 s |
| caption served as `smi/caption`, CRLF | `text/*` is wrong for Samsung |
| DIDL `<res>` carries size/duration/bitrate/resolution | without it `TrackDuration` reads `0:00:00` |
| `X_ControlCaption` is opt-in | the DIDL `sec:CaptionInfoEx` already binds the subtitle |
| write-gap timing | the TV's reader uses `select()` with a 5000 ms timeout (`0x1388`) and 3 attempts |
| `--nopoll` | polling costs the renderer 2 fresh TCP connections per call |

## Build for the router

The RV6699 is **MIPS32r1, big-endian, soft-float**. Debian's
`gcc-mips-linux-gnu` produces MIPS32r2 + hard-float and the binary dies with
`Illegal instruction` on this chip — the same wall the dropbear build hit. Use a
musl-cross-make toolchain:

```bash
git clone --depth 1 https://github.com/richfelker/musl-cross-make
cd musl-cross-make
printf 'TARGET = mips-linux-muslsf\nOUTPUT = /opt/cross\nGCC_CONFIG += --with-arch=mips32\n' > config.mak
make -j"$(nproc)" && sudo make install
export PATH=/opt/cross/bin:$PATH
```

The build uses the **built-in** `mips-unknown-linux-musl` target (already
big-endian, already `+soft-float`) and downgrades the ISA from its r2 default to
r1 with `-C target-cpu=mips32`. A hand-written `.json` target was tried first and
abandoned: the `libc` crate keys its cfgs off the triple, so a custom name like
`mips-unknown-linux-muslsf` makes it fail to compile. Verified against the
router's own busybox: `e_flags 0x50001007` -> arch bits `0x50000000` = MIPS32
(r1) with the soft-float bit set.

It is a tier-3 target, so `core`/`std` are compiled from source:

```bash
rustup toolchain install nightly --profile minimal
rustup component add rust-src --toolchain nightly
cargo +nightly build --release      # target + flags come from .cargo/config.toml
```

Note `AtomicU64` does not exist here (`max-atomic-width = 32`), which is why the
counters are `AtomicUsize` and the byte total sits behind a `Mutex`.

Or just run the bundled workflow (`.github/workflows/build-mips.yml`,
`workflow_dispatch`) and grab the `captioncast-mips` artifact — that is how the
dropbear binary for this router was produced.

Sanity-check before copying it over:

```bash
readelf -h captioncast | grep -Ei 'data|machine|flags'   # 2's complement, big endian / MIPS
readelf -A captioncast | grep -i abi_fp                  # Tag_GNU_MIPS_ABI_FP: 3 (soft float)
```

## Deploy

The router's `/var` is a ramfs and small, and `/tmp` is only ~32 MB — a 9 MB clip
fits but leaves little room. Put the binary on the persistent rootfs and the
media wherever there is space:

```bash
scp -i ~/.ssh/rv6699_key -P 2222 captioncast SuperUser@192.168.1.254:/var/
scp -i ~/.ssh/rv6699_key -P 2222 media.mp4  SuperUser@192.168.1.254:/var/
ssh -i ~/.ssh/rv6699_key -p 2222 SuperUser@192.168.1.254
  chmod +x /var/captioncast
  /var/captioncast --tv 192.168.1.70 --media /var/media.mp4 --nopoll
```

The clip must be **faststart** (moov up front) — the parser only reads the first
2 MB looking for `mvhd`, and a TV that has to scan a whole non-faststart file
will not start reliably either.

## The bundled clip, and why it is not `testsrc2`

`media.mp4` (941 KB, 34 s, 221 kbit/s) is generated, not filmed:

```bash
ffmpeg -f lavfi -i "testsrc=size=1280x720:rate=30" \
       -f lavfi -i "sine=frequency=440:sample_rate=48000" -t 34 \
       -c:v libx264 -profile:v main -level 4.0 -pix_fmt yuv420p -r 30 \
       -crf 23 -preset slow -g 30 -keyint_min 30 -sc_threshold 0 \
       -c:a aac -b:a 48k -ac 1 -ar 48000 -movflags +faststart media.mp4
```

Measured alternatives for the same 34 s at 720p30 CRF 23:

| source | size | bitrate |
|---|---|---|
| `testsrc2` | 13.5 MB | 3182 kbit/s |
| **`testsrc`** | **941 KB** | **221 kbit/s** |
| `smptebars` | 310 KB | 73 kbit/s |
| solid colour | 291 KB | 69 kbit/s |

`testsrc2` is a codec stress pattern — moving noise and hard edges — so it costs
an order of magnitude more bits than anything else while showing nothing extra.
Re-encoding an existing `testsrc2` clip at CRF *grows* it (CRF 20 came out at
135 % of a 2000 kbit/s-capped original, because the encoder now also preserves
the original's artefacts). The fix is a cheaper source, not a smaller bitrate.

`testsrc` was picked over the even smaller static options because it renders a
**frame counter and timecode into the picture** — with it on screen you can see
how far playback actually got, which is precisely what is hard to tell from the
network side.

## Usage

```
--tv <ip>          target renderer            (default 192.168.1.70)
--media <path>     mp4 to serve, faststart    (default ./media.mp4)
--port <n>         local HTTP port            (default 8099)
--status           read-only: transport + caption state, then exit
--stop             Stop playback + disable the caption, then exit
--no-caption       A/B control: same media, no subtitle bound
--ctrl-caption     also fire X_ControlCaption(Enable) during playback
--remote [url]     point the TV at a remote clip, bypassing our server
--nopoll           do not poll the renderer while it streams
```

Running it from the router rather than a PC also removes one wireless hop from
the media path: the router is the AP, so it reaches the TV directly instead of
PC → AP → TV.
