# Stage 1 application selection and first usable endpoint

Status: initial application endpoint qualification; complete suite, cache
conditions and attribution remain open. No B0/B1/B2 application comparison or
new accelerator benefit is claimed.

## Installed candidates and selection

The [read-only inventory](evidence/stage1-workload-inventory.json) pins its own
source, package versions and Steam build IDs. It reads selected installation
manifests and bounded filename-suffix counts. It does not read accounts, saves,
browser profiles or application preferences. Public output contains no home
paths, session addresses or process IDs. It starts no application and changes
no cache or device setting.

| Candidate | Observed version/build | Observed asset examples | Current endpoint status |
| --- | --- | --- | --- |
| Konsole | 26.08.1-1.1 | Executable/libraries | Three functional PTY-ready launches pass |
| Firefox | 156.0.1-1.1 | Controlled offline document still to define | Unqualified |
| PRAGMATA | Steam build 24543093 | Six `.pak` files | Historical title marker only; requalification needed |
| CONTROL Resonant | Steam build 25767184 | `.rmdblob` / `.rmdtoc` | Menu/scene and route unqualified |
| Borderlands 4 | Steam build 26007962 | `.pak` / `.ucas` / `.utoc` | Held-out loading/streaming candidate, unqualified |

Suffixes are observed storage formats, not measured compressibility or engine
attribution. The bounded inventory examines at most 10,000 files per installed
application, through depth four, and reports truncation. A build ID or suffix
inventory does not pin all input bytes, dependencies or mutable state.

[Selection v1](../bench/workload-selection-v1.json) records the candidate mix
before new performance comparisons: tentative weights are 20% desktop startup,
10% private package update, 40% game loading and 30% game streaming. Borderlands
4 and concurrent memory pressure remain held-out regression candidates. These
are **tentative selection weights, not a frozen complete suite**. Resolve input,
endpoint, replay and cache feasibility, then freeze the final contract before
B0/B1/B2 or accelerator comparisons. Never select/reweight using observed gains.
Any feasibility-driven change must retain the old selection and its reason.

## Konsole endpoint contract

`bench/terminal_endpoint.py` runs as the existing desktop user, without root.
It launches a separate `--nofork` Konsole with new private configuration, data
and cache directories for each trial. It executes its Python helper directly,
without a shell, user startup commands or history. Normal application rendering
and system libraries are used. No persistent application preference is edited.

The helper must receive a real terminal, send a cursor-position query and receive
a syntactically valid terminal response with a nonzero terminal size. It then
sends a nonce and monotonic timestamp through a private Unix socket. The parent
checks the peer's kernel credentials and ancestry against its own launched
terminal, nonce, timestamp ordering and that the terminal is still alive. A
message from an unrelated process or mere process appearance is insufficient.

The endpoint is **Konsole PTY operational readiness**. It does not prove the
first composited frame, visible window presentation, full desktop interaction or
game usability. A first-frame claim requires a separate compositor/visual
marker. The timer includes launch through the helper's valid terminal reply;
parent receipt delay is also recorded. Only the owned helper/window is closed,
normally by finishing the helper and waiting for the window process to exit.
Timeout cleanup targets that launched process, never an application-name match.

The final source passes three launches with marker times of 187.149, 195.569 and
196.711 ms. Every peer passes ownership checks, CPU policy stays fixed and every
window closes normally with exit status zero. These times establish a working
endpoint; they are **not a cold-start baseline or an acceleration result**. An
earlier source also passed three functional launches and is retained privately.
Review found an EOF-handling edge in its marker reader; the final reader rejects
a closed partial frame immediately. Real-socket counterexamples reject partial
EOF, oversized frames and multiple JSON messages, and preserve integer clocks.
The Linux suite passes 134 tests.

Each launch has fresh private settings/cache, while the **system page cache is
uncontrolled**. No cache eviction occurs. System library/font/plugin inputs,
first-run state, activity exclusions and cold/warm procedures must be qualified
before comparing storage policies. Mapped `/usr` dependencies are recorded
privately for that next input audit; they do not capture every accessed file.

The [final-source result](evidence/stage1-terminal-endpoint.json) includes source
and executable hashes, explicit endpoint limits, all three rows and normal
closure evidence. Detailed environment/mapping/process logs stay private.

```sh
python3 bench/workload_inventory.py > reviewed-inventory.json
python3 bench/terminal_endpoint.py run \
  --output /absolute/owned-lab/new-terminal-endpoint --trials 3
```

Outputs must be new and their parent must be owned and not group/world writable.
The probe allows at most six launches, bounds waits and marker size, and retains
failed evidence. This is an opt-in development tool, not a startup service.

## Actual operation-class diagnostic

The installed kernel's `blk_types.h` defines an eight-bit operation field and
`REQ_OP_FLUSH = 2`; its SHA-256 is recorded in the inventory. The [offline
diagnostic](evidence/stage1-request-classes.json) validates the original trace
wire accounting, then counts operation/size/flag classes in all five strict
failed windows of the retained three-condition comparison. All 11 flagged
records are operation 2, zero requested/completed bytes, flag 144 (missing
insert plus zero bytes). No flagged read records appear in those five windows.
There are also 11 unmatched completion callbacks in the global counter.

The equal totals do **not** identify which requests generated the unmatched
callbacks or prove their cause. The [upstream flush implementation](https://github.com/torvalds/linux/blob/master/block/blk-flush.c)
constructs separate flush requests and documents multi-step completion behavior.
That supports a lifecycle hypothesis; upstream master is not the source of this
custom compiled kernel. Its installed build tree lacks those block sources. Neither a
matching count nor upstream source proves the actual callback relationship.

`analysis/request_classes.py` requires an explicitly supplied operation number,
keeps all flag classes and orphan totals, and never recomputes a qualification
verdict. A counterexample confirms that a zero-byte read is not classified as a
flush or used to erase failure. Original screen results stay unchanged.

```sh
python3 analysis/request_classes.py \
  --trace /absolute/private-capture.json --flush-operation 2
```

Next, observe the actual kernel's operation/size and lifecycle at unmatched
completion, or use another qualified correlation method, with bounded private
diagnostics. Keep read/write error, partial completion and genuine identity/loss
cases distinct. No quality rule should be relaxed until that evidence exists.

## Next gate work

1. Pin the terminal's complete inputs and qualify cache state, activity rules
   and a compositor marker if first-frame timing is required.
2. Qualify a private offline Firefox usable-document marker and private package
   update procedure; preserve separate application state and normal launch paths.
3. Back up/isolate mutable game state, requalify the title marker, and establish
   scene/replay routes plus frame events. Title-screen timing is not streaming.
4. Resolve flush/unmatched-completion semantics, measure probe cost and extend
   dependency/fault/filesystem/decompression attribution before comparisons.
5. Freeze the full suite and final weights, then run controlled B0/B1/B2 with
   individual regressions, uncertainty and maintenance/resource costs reported.
