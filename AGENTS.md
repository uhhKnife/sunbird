# AGENTS.md

Phoenix Unlock patches Phoenix, Discord's native Rust client, and runs TypeScript plugins inside it. The mobile target is build 356.7 Alpha (`versionCode` 356207). "Phoenix" is Discord's client; the runtime, crates, and plugin global are all named `phoenix`.

Read this file before changing code. Every fact here cost someone hours to learn.

## Hard rules

- Credentials: Phoenix's HTTP requests cross `GuestHost.invoke` carrying the user's `authorization` header. Never log, print, or save invoke frames, dispatch frames, or request headers. Filter before writing anything to disk and delete any capture that holds a token (`discord.rs` keeps session headers in memory only).
- Secrets in logs: plugin settings of `type: "secret"` are scrubbed from every console line by `console.rs`. Any new credential-bearing setting must use that type.
- Privacy: screenshots and logs from owners' phones show private chats, emails, and accounts. Never quote them in commits or replies, never commit them, and delete them after use.
- Real accounts: never send account-mutating requests (friend adds, settings PATCHes, guild joins) to test something. Test `phoenix.discord` writes against paths that return 404, and never inject fake messages into real channels.
- Signing: every APK from the patcher CLI, the site, or the in-app updater is signed with `crates/patcher/keys/` (linked by the runtime through patcher), v3 only, with the rotation proof from the old Valenced test key so builds install over each other without losing login. Never add the old private key; read `keys/README.md` before touching signing.
- Plugin API lives in Rust: UI ops, patch targets, settings pages, stores, and HTTP live in the crates and reach plugins through `phoenix`. Plugins stay thin TypeScript with no JS prelude in the runtime.
- Typed boundaries: plugins get opaque handles (`phoenix.gateway.messageCreate`), not raw strings like `"MESSAGE_CREATE"`. Read event, prop, and handler lists live from the binary instead of hand-maintained list files.
- No committed build output: `web/plugins/lib*.so` and `web/pkg/` are built by `scripts/site.nu`, plugin bundles by `web/tools/bundle-plugins.ts`. The Frida gadgets in `web/plugins/frida-*` are the one exception (kept for x86 WSA debugging).
- Test on a device before pushing: a clean build proves nothing about the bridge.

## Layout

| Path | What |
|---|---|
| `crates/loader` | `libphoenix.so`, injected into the APK as `libplm.so` (and desktop loader library). Its constructor starts the runtime. |
| `crates/runtime` | QuickJS plugin runtime and the shared `phoenix` API (`phoenix.d.ts` is the plugin API reference; `platform.rs` defines the `Platform` trait). |
| `crates/runtime/src/gateway.rs` | Gateway event hooks by swapping handler pointers in Phoenix's event registry. |
| `crates/runtime/src/discord.rs` | `phoenix.discord`, Discord's API with Phoenix's own session (platforms carry the requests). |
| `crates/runtime/src/update.rs` | Update checks against the site and one-tap plugin updates. |
| `crates/runtime/src/remote.rs` | Debug shell on `127.0.0.1:4242` (off by default on Android, toggled in Settings -> Phoenix Unlocker -> Debug; on desktop starts when DevTools first opens or at launch with `SUNBIRD_DEVTOOLS` set, which `dev.ps1 -Desktop` does). Platforms add their own endpoints. |
| `crates/runtime-mobile` | Mobile runtime for Android and iOS. iOS has no installer or staff hook, and uses Foundation HTTP plus a bundled SQLite. |
| `crates/runtime-mobile/src/bridge/` | Sinks every guest/host frame passes, returning `Action::{Pass, Drop, Replace}`. `jni.rs` patches the JNI table on `GuestHost.invoke`/`applyOps` and rebinds `nativeDispatch`; `ios.rs` swaps the dispatch slot in the guest's vtable and the call slot in the host callbacks' vtable. |
| `crates/runtime-mobile/src/settings/` | Mobile Phoenix Unlock settings pages built from UI ops. |
| `crates/runtime-mobile/src/patches/` | UI patch targets, slash commands, profile tabs, and emoji picker. |
| `crates/runtime-mobile/src/discord.rs` | Plugin requests to Discord through Phoenix's own `Networking` module. |
| `crates/runtime-mobile/src/host.rs` | Phoenix's host call, event, and field numbers, read at startup from the installed APK's dex name table or the host's Swift name table on iOS (`host::send` and `host::ask` call host modules). |
| `crates/runtime-mobile/src/picker.rs` | File picker, toasts, clipboard, and links through Phoenix's host modules. |
| `crates/runtime-mobile/src/install.rs`, `loader.rs` | APK self-update and Android's installer opened through Discord's `FileProvider`. |
| `crates/runtime-desktop` | Desktop runtime for `Discord.exe`, Linux `discord-phoenix`, and macOS `Discord`: access gate, HTTP transport hooks, Sunbird pages in User Settings, message accessories, and the tray (`os.rs` holds per-OS code). |
| `crates/ui-mobile` | Typed codec for mobile UI-op batches (`src/props.in` is Phoenix's prop table, `templates.json` holds captured layouts, `motion.rs` drives native springs, `mirror.rs` keeps a live view tree for host tests). |
| `crates/ui-desktop` | Desktop UI host primitives (clipboard, URLs, notifications, tray, GPUI surface hooks), one file per OS. |
| `crates/wire` | Tagged values and bridge frames (`HostCall`, `DispatchEvent`). |
| `crates/hook` | Image scanner, `swap_words`, and ShadowHook through `sunhook-sys` on Android ARM. |
| `crates/sigs`, `crates/sigscan` | Gateway registry walk, handler ABI, and binary locators (`desktop.rs`, `mobile.rs`, `macos.rs`). `sigscan` dumps a library's registry, runs `check` (every locator for that platform, exit 1 on a miss), and looks up strings, refs, and disassembly. |
| `crates/patcher` | Patches and signs split APKs as a library and CLI (merged single APK or individually signed splits). |
| `crates/patcher-web` | `crates/patcher` compiled to wasm for the site. |
| `crates/stand-in*` | Fake gateway library and demo to test hooks without Discord. |
| `plugins/*/src/index.ts`, `manifest.ts` | Bundled plugins. `manifest.ts` exports a `Phoenix.Manifest`, which `web/tools/bundle-plugins.ts` writes as the `// @` lines opening the bundle, the only bundler `phoenix.nu` and `dev.ps1` use. `warning` shows on the site, `unlisted` keeps a plugin off the site and out of updates, and `permissions` grants APIs, which `crates/runtime/src/permissions.rs` refuses otherwise. |
| `docs/phoenix-356207.*` | Phoenix schema extracted from the APK by `scripts/extract-schema.py`: 29 view kinds, 855 props, 79 host modules with 433 methods, 109 events, 286 `ic_mana_*` icons, and accessibility ids. Read this before decompiling. |
| `web/` | What CI deploys to assets.sunbird.tools with a `site.tar.gz` that `sunbird-tools/site` builds from (patcher wasm, loader libs, plugin bundles, `version.json`). Builds before `76bc0d7` fetch the last three from sunbird.tools, so the site keeps serving them at the same paths. |
| `frida/` | Optional Frida gadget bootstrap for x86 debugging. |
| `scripts/*.nu` | `phoenix.nu` builds, patches, and installs on a phone; `site.nu` builds the site's native libs and wasm. |
| `scripts/sunbird-{linux,macos}.sh` | Desktop installers served by the site. Each creates a launcher that fetches the loader before every start and leaves Discord's own files untouched. |
| `scripts/dev.ps1` | Windows dev loop (details below). |

## Building

- Linux: run `nix develop`, then `nu scripts/phoenix.nu base.apk config.<abi>.apk config.<dpi>.apk config.<lang>.apk` (the ABI split is `config.arm64_v8a` or `config.armeabi_v7a` and picks the loader target). The devshell provides SDK, NDK, and JDK. `phoenix.nu` ends in a blocking `adb logcat` tail, so background it when calling from a tool.
- Windows (without Nix): use Rust `stable-x86_64-pc-windows-gnu` with target `aarch64-linux-android`, `cargo-ndk`, an NDK, a JDK, and an Android SDK with a platform and build-tools in `ANDROID_SDK_ROOT` (Cargo fetches ShadowHook as `sunhook-sys`). Set `LIBCLANG_PATH` to an LLVM `bin` directory holding `libclang.dll`, and pass `BINDGEN_EXTRA_CLANG_ARGS_aarch64-linux-android="--target=aarch64-linux-android28 --sysroot=<ndk>/toolchains/llvm/prebuilt/windows-x86_64/sysroot -isystem <ndk>/.../lib/clang/<ver>/include"` via `env` because the variable name contains hyphens. Git for Windows' MinGW (gcc 12) can't link host build scripts, so take it off `PATH` and put a directory with only `dlltool.exe` (from the toolchain's `self-contained`) and `as.exe` plus its DLLs on `PATH`. Build with `cargo +stable-x86_64-pc-windows-gnu ndk -t arm64-v8a -P 28 --link-builtins build --release -p phoenix-loader`, then `cargo build --release -p patcher`.
- iOS: `.github/workflows/ios.yml` builds `libphoenix.dylib` for `aarch64-apple-ios` on macOS (the SDK ships only with Xcode).
- macOS: `cargo build --release -p phoenix-loader` builds `target/release/libphoenix.dylib` for Desktop Phoenix. Install via `SUNBIRD_SITE=http://127.0.0.1:<port> sh scripts/sunbird-macos.sh` against a local folder serving `version.json` and `plugins/libphoenix-macos-arm64.dylib`, or run the copied app by hand (see Host facts). `sigscan` builds natively on Apple silicon.
- Site: run `nu scripts/site.nu web` and `node web/tools/bundle-plugins.ts` (set `ESBUILD` if esbuild isn't on `PATH`), then `nu scripts/fetch.nu <this checkout>` in `sunbird-tools/site`. CI deploys the same files to assets.sunbird.tools on pushes to `main` and the site picks them up within 10 minutes.

## Fast loop

1. Check `docs/phoenix-356207.md` or `.json` before decompiling. After a Discord update, regenerate them with `python scripts/extract-schema.py <dir with the splits>`.
2. Run `.\scripts\dev.ps1 -Test` to run host tests for `phoenix-ui-mobile`, `phoenix-ui-desktop`, and `phoenix-wire` in under a second.
3. Turn on the debug shell once on the phone (`dev.ps1` forwards port 4242):
   - `-HotReload <plugin>` reloads a plugin in ~200 ms without rebuilding the APK.
   - `-Eval "<js>"` runs a snippet (for example `phoenix.ui.root()`).
   - Prototype UI or API patches in JS via `phoenix.ui.mount`, `phoenix.bridge.invoke`, `phoenix.discord.onRequest`, and `onResponse`, then move finished primitives into Rust.
   - `-Logs`, `-Ops [filter]`, `-Events [filter]`, and `-Tree [node]` inspect console output, decoded UI-op batches, view/host events, and the mirrored view tree. `-Clear` empties the ring buffers before a repro.
4. `.\scripts\dev.ps1` builds with `dev-fast` (~15 s incremental), patches, installs, and launches (`-SkipBuild` only rebundles plugins and repatches; `-Release` builds release).
5. On Desktop Phoenix, `.\scripts\dev.ps1 -Desktop` builds the DLL, copies plugins, and restarts Discord through the injector. Every debug-shell switch above takes `-Desktop` and skips adb (`-Ops` and `-Tree` stay Android-only since desktop has no UI-op stream). Reverse desktop binaries with `.\scripts\dev.ps1 -Sigscan check|strings|refs|dis ...` on `Discord.exe` (a panic message or event name usually leads straight to the caller) or `phoenix.native` inside `-Eval` (console only, never plugins: `strings`, `refs`, `fn`, `dis`, `scan`, `read`, `readU64`, `readStr`, `hook(addr, limit)`, `unhook(id)`, `hooks()`). Hooks log each call's `rcx rdx r8 r9`, pointed bytes, and caller to `-Events` as RVAs like `+0x7711630` (matching `sigscan`). `-Events` also shows every gateway event by name/size and Discord API requests by path.
6. Keep agent and subagent turns fast: iterate with `dev-fast` (`.\scripts\dev.ps1 -Desktop`, no `-Release`) and save `-Release` for final verification; batch reads, edits, and shell steps (`test && build && launch` in one command); use compiled `sigscan` or `phoenix.native` instead of scanning the 515 MB `Discord.exe` `.text` section with Python loops or regexes; reserve high-effort subagents for hard reverse-engineering and pass exact file paths and build env in the brief.

The debug shell answers anyone on loopback and `/eval` runs JS with the Discord session. Leave it off outside development.

## Code style

- Formatting: Rust is edition 2024, 3-space indent, width 100, pinned in `.rustfmt.toml` (which sets `unstable_features = true`). Run nightly rustfmt on touched files only, or match the surrounding 3-space style by hand. Never run stable rustfmt or `cargo fmt`, and keep diffs free of unrelated formatting churn outside touched hunks.
- Lints: workspace lints enable clippy pedantic and nursery and deny `unsafe_op_in_unsafe_fn`. Keep clippy clean on the host, `aarch64-linux-android`, `armv7-linux-androideabi`, and any affected desktop or iOS targets (`x86_64-pc-windows-gnu`, `x86_64-unknown-linux-gnu`, `aarch64-apple-ios`) when touching shared crates. Never widen the workspace lint list; scope `#[expect(lint, reason = "...")]` to the one function that needs it.
- Unsafe blocks: every `unsafe` block needs a short `// SAFETY:` comment stating the actual invariant (buffer bounds, live pointer provenance, single-threaded init) rather than restating the call.
- Errors: use flub in libraries and misstep in binaries. Untrusted input, including anything read from Phoenix, returns an error and never panics (a panic inside Discord's process kills the app).
- Binary locators: anything that finds addresses or offsets in Discord's binaries lives in `crates/sigs` and returns `Found`, so `sigscan check` and the check workflow cover it on every new build. Never fall back to a hardcoded offset seen on one build; when it doesn't decode, leave that feature off.
- Types: return named enums over nested `Option`s, and use serde structs over raw `serde_json::Value`.
- Comments: say why, and only when the reason isn't obvious from the code (a host quirk, a measured number, a version). No comments that restate code or narrate history, and no em dashes in comments, docstrings, or commit messages (use commas, colons, or parentheses).
- Commits: subjects read `area: lowercase imperative` (for example `runtime: add select settings`). Bodies are optional and explain why. Never add AI co-author trailers.

## Replies

- Verdict first: open with the answer, outcome, blocker, or side-effect boundary (`done locally, nothing committed or pushed`). Never open with greetings, validation, or process narration.
- Epistemic honesty: separate directly observed and verified facts from inferences or untested assumptions. Never claim or imply a check passed if it didn't run.
- No sycophancy: push back directly on leading questions when the honest answer is no. Own bugs and reverted attempts flatly in one line without groveling, and take criticism without defensiveness or flattery.
- Facts vs. product calls: keep engineering facts separate from product or design calls, state a concrete recommendation, and hand the decision back explicitly.
- Match length to the ask: a casual ping or yes/no gets one line; a quick factual lookup gets one or two sentences with no headings or lists; multi-part work or audits get a dense, evidence-backed brief with exact file/line references and concrete numbers instead of vague adjectives.
- Progress updates: emit one short line only for real milestones, newly found constraints, or the next build/test stage. Never narrate routine file reads or searches.
- Formatting: use normal sentence case and natural contractions. Default to 1-3 short prose paragraphs instead of bullet lists; only use flat `- ` bullets for genuinely parallel, scannable items, and avoid bold-prefix bullets (`- **label:** ...`). Prefer standalone bold labels (`**What changed**`, `**Measured**`, `**What's left**`) over nested headings, numbered lists only when order matters, and tables only for compact comparisons. Keep backticks sparse (write tool names, crate/module names, lint groups, section titles, and general concepts in plain prose; reserve backticks for exact copyable commands, flags, literal config values, commit hashes, or ambiguous symbol names). Explain how and why in prose, reserve fenced code blocks for copy-pasteable commands or requested snippets, and tuck caveats and verification status into inline parentheticals.
- No filler or noise: no em dashes (use commas, colons, or parentheses), no emojis, no status checkmarks, no horizontal rules, no prose exclamation marks, and no AI boilerplate (`certainly`, `absolutely`, `of course`, `great question`, `happy to help`, `in summary`, `overall`, `delve`, `comprehensive`, `robust`, `seamlessly`, `leverage`, or pushy closing questions). Stop cleanly on the final state, proof, or declarative next step.

## Testing on a phone

- Install over existing `com.discord` with `adb install-multiple -r` so login survives.
- Read logs with `adb logcat -s phoenix` (`-s FridaPlugins` for Frida) and fail fast: match `error[E`, `error:`, and panics alongside the success line, and never block for minutes waiting on lines that require live chat traffic.
- Open settings via `adb shell am start -a android.intent.action.VIEW -d discord://app/settings com.discord`.
- Locate views with `uiautomator dump` by resource id (Phoenix's accessibility id; ours are `phoenix-<title>`). Tap by dumped bounds, never guessed coordinates (a blind tap once opened a reply draft in a real channel).
- Owners deploy to the same phone while you work. If expected logs vanish, check the pid and startup log to see whose build is running before debugging, and ask before installing over theirs.
- Never enter passwords, and remove any test plugins or files you add.
- Git Bash on Windows rewrites `/word` into a path in adb arguments; set `MSYS_NO_PATHCONV=1` and pass local paths through `cygpath -w`.

## Host facts

Read the decompiled host before guessing or bisecting. `jadx -q -j 16 --no-res -d out <base apk>` decompiles Java. The native host is `lib/arm64-v8a/liblibdiscord_wasm_host.so` (97 MB, stripped, JNI exports visible to `nm -D`); the `armeabi-v7a` copy is 68 MB of Thumb-2 and inlines differently, so an arm64 byte pattern says nothing about arm32.

**Hooks and update risks**
ShadowHook comes from `sunhook-sys` (`sunbird-tools/sunhook`). On arm32 no island fits inside the host library, so a hook rewrites the first 8 or 10 bytes of its target in place. Install hooks from the loader's constructor before any thread can be inside the target, and pass Thumb targets with bit 0 set or ShadowHook writes an ARM jump. On Discord updates, watch `crates/ui-mobile/src/props.in` (props are indexed by position, so new props shift later indices), `GuestHost.d(byte[], Function0)` (obfuscated), and `templates.json`. Host module, method, event, and field numbers are read at startup by `host.rs`, so the numbers below are for hand-reading frames; everything else is resolved by names, strings, and patterns.

**Threads, invoke frames, and networking**
Never send UI ops from the main thread (Rust may hold the UI lock while waiting on Java); the settings worker sends them. Java only honors `WasmRuntime.nativeDispatch` on the `wasm-guest` HandlerThread and silently drops calls from other threads. Queue a frame from any thread via `GuestHost.d([B, Function0)` without its 4 zero header bytes, and mark re-sent frames so they don't loop back through dispatch sinks. Invoke frames start with a 16-byte header (kind u8: 1 call, 3 event, 4 batch; zero byte; module u16; method u16; u16 0; call i32; args length u32) followed by a tagged args record and raw body. Module, method, and field numbers index the name table in `hh/jb.java` (strings like `"Networking.request 168"`), and host events return as kind-3 frames inside kind-4 batches through `nativeDispatch`. Networking is module 43 (request 168, cancel 167, upload 169, reply event `@http` 321): request fields are id 417, method 421, url 422, headers 423 (array of `[name, value]`), responseHeaders 424; reply fields are id 417, status 430, headers 423 (map), error 403. Java's side is a plain OkHttp executor and the guest sets every header including `authorization`.

**Gateway, UI, stores, and QuickJS**
`READY` never passes through the gateway registry on 356207, so patches rewriting `READY` don't apply; `LIBDISCORD_REDUCERS_TABLE` is an exported second registry with 86 more events and no overlap. Desktop's session parses READY itself too, from the text under 2 MB and from its own payload above, and `runtime-desktop/src/ready.rs` hooks both; READY carries `user_settings_proto` only when the cached settings' version differs from Discord's, and then Phoenix's settings code also takes READY through the registry, so READY hooks can run twice on Desktop. Motion has 65536 animation slots (ids >= 65536 are dropped silently); Phoenix allocates upward from 0 so ours allocate downward from 65535, and reused slots keep a dead view's spring until re-sprung (channel numbers are cases of `mh/e0.d`; `animate` only applies to images). Text and inputs take `spans` and `valueSpans` arrays of `{text, color, weight, italic, bg}` pieces; set an input via `forceValue {seq, text, start, end}` (applied on `seq` change; `value` is ignored while the keyboard has edits in flight). The message list is virtualized: a row event's `index` is absolute and the list's `first` prop is its first mounted child, so the row is `kids[index - first]`. State lives in `files/store/<account>/cache.sqlite` (tables of `k` and JSON BLOB `v`; message keys end in the id zero-padded to 20 digits). Phoenix fills the edit box from the stored message, so a hook rewriting your own `MESSAGE_CREATE` changes what an edit posts (the runtime restores original text in the composer). QuickJS has no `URLSearchParams` (check other web globals before using them in plugins). Discord payload shapes are documented at https://docs.discord.food/.

### macOS Desktop

**App bundle, launcher, and environment**
`Discord Phoenix.app` uses the hardened runtime, so dyld ignores `DYLD_INSERT_LIBRARIES`. `sunbird-macos.sh` clones it (`cp -c`, free on APFS) into `~/Library/Application Support/Sunbird/Sunbird.app`, renames it, sets `DYLD_INSERT_LIBRARIES` and `SUNBIRD` in its Info.plist `LSEnvironment`, and ad-hoc signs it (Discord relaunches itself with bare `open -n`, which would drop a launcher's `--env`; after an update the loader rewrites Discord's relaunch script to open `$SUNBIRD`, which re-signs the newer copy, and quits any uninjected copy first). In-place patching was rejected because writing into the bundle needs App Management with SIP on, dyld refuses to launch if the library is missing, each update swaps the bundle, and a Developer ID wouldn't cover keychain or App Group entitlements bound to Discord's team id.

Phoenix re-execs itself once with its malloc settings and `DISCORD_DESKTOP_MALLOC_REEXEC=1` unless `LSEnvironment` already set them, so the loader starts only in the final image (with SIP off, dyld kills any arm64e child like `osascript` or `nohup` that inherits an arm64 library). Data lives in `~/Library/Application Support/libdiscord` (or `LIBDISCORD_DATA_DIR`), with Sunbird's home in its `sunbird/` subdir; tokens stay in the login keychain, so pointing `LIBDISCORD_DATA_DIR` elsewhere still signs into the owner's accounts.

**Logs, debugging, and arm64 hooks**
Stream logs with `/usr/bin/log stream --predicate 'eventMessage CONTAINS "phoenix:"'`. After killed launches, pass `--args -ApplePersistenceIgnoreState YES` or macOS's "reopen windows?" alert stalls Discord; opening a `discord://-/channels/<guild>/<channel>` URL with `open -a <copy>` loads a channel without manual input. The binary has no symbols (`sigscan strings`/`refs`/`flat` resolve `adrp` pairs and outlined stubs); lldb attaches over ssh once Developer Mode is on (`DevToolsSecurity -enable`), using `script dbg = lldb.debugger; threading.Timer(n, lambda: dbg.GetSelectedTarget().GetProcess().SendAsyncInterrupt()).start()` + `detach` to end waits (never set `process handle SIGTRAP -p true`, which kills Discord).

`__TEXT` never takes `PROT_WRITE`, so `Image::write_code` remaps via `vm_protect(VM_PROT_COPY)`. Arm64 `hook_entry` overwrites 4 instructions with `ldr x16,#8; br x16; .quad` and refuses literal loads or branches back into them (follow a lone `b` target first). For large returns, x86 passes the return slot first while arm64 passes it in `x8`; because `gpui.rs` and detours use x86 order, arm64 calls out through `image::sret_caller` and enters detours through `image::sret_callee`. `Pattern::new` panics without a literal byte (and a panic in the loader constructor aborts Discord), so pass the x86 frame prologue to arm64 `hook_entry`, which ignores it.

**Gateway and UI**
macOS keeps message, reaction, presence, and typing events in a flat table apart from the domain tables (in two copies, dispatching `MESSAGE_DELETE` through the second; `MESSAGE_CREATE` is also in it with a different handler than the domain table's unused one), so `registry.rs` swaps both copies and takes the flat table's handler. Plugin pages and dialogs use AppKit windows (`ui-desktop/src/macos/panel.rs`), and Command-Shift-I opens DevTools through an `NSEvent` local monitor while Discord is focused.
