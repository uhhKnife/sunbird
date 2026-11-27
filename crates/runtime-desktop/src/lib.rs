//! phoenix on Desktop Phoenix: the access gate, the HTTP transport hooks, the
//! Sunbird pages in User Settings, message accessories, member list
//! decorations and the tray.

#![cfg(any(
   windows,
   target_os = "macos",
   all(target_os = "linux", target_arch = "x86_64")
))]

mod accessories;
mod badges;
mod composer;
mod context_menu;
#[cfg(target_arch = "x86_64")]
mod counts;
mod discord;
mod double_click;
mod emoji;
mod fetch;
mod gateway_send;
mod gpui;
mod gpui_theme;
mod headers;
mod icons;
mod js;
mod members;
mod message;
mod modal;
mod os;
mod ready;
#[cfg(windows)]
mod restart;
mod settings;
mod shortcuts;
mod sidebar;
mod staff;
mod sticker;
mod stream;
mod theme_css;
mod toolbar;

use std::{
   ffi::c_void,
   path::{
      Path,
      PathBuf,
   },
   sync::{
      Arc,
      Mutex,
      PoisonError,
   },
   time::Duration,
};

use phoenix_hook::{
   image::Image,
   x86::Abi,
};
use phoenix_runtime::{
   Error,
   Notice,
   Platform,
   Plugin,
   Started,
   discord::{
      Authorization,
      DiscordError,
   },
   fetch::{
      FetchError,
      Request,
      Response,
   },
   remote::{
      self,
      Done,
   },
   store::{
      Rows,
      StoreError,
   },
};
use phoenix_sigs::{
   desktop::{
      Prologue,
      Prologues,
   },
   registry::GatewayRegistry,
};
use rquickjs::{
   Ctx,
   Object,
};

struct Desktop;

/// A `POST /ui/choose` or `POST /ui/sheet` body.
#[derive(serde::Deserialize)]
struct DialogRequest {
   title:     Option<String>,
   message:   Option<String>,
   text:      Option<String>,
   monospace: Option<bool>,
   highlight: Option<bool>,
   options:   Option<Vec<DialogItem>>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum DialogItem {
   Label(String),
   Item {
      label:  String,
      #[serde(default)]
      danger: bool,
   },
}

#[derive(serde::Serialize)]
struct DialogAnswer {
   index: i32,
}

/// Whether Discord's code is x86-64, which every locator in
/// `phoenix_sigs::desktop` and `http` decodes. macOS Phoenix is arm64 only, so
/// there they are never run, an x86 patch can never land in arm64 code, and
/// what they locate stays off.
pub(crate) const X86_CODE: bool = cfg!(all(target_arch = "x86_64", not(target_os = "macos")));

/// Hooks `target` with `detour` past the prologue `pick` chooses, and returns
/// the trampoline as `F`, or logs the error after `what`.
///
/// # Safety
///
/// Runs before Discord's threads reach `target`, `detour` has its ABI, and `F`
/// is its function pointer type.
pub(crate) unsafe fn hook<F: Copy>(
   image: &Image<'static>,
   pick: fn(Prologues) -> Prologue,
   target: usize,
   detour: usize,
   what: &str,
) -> Option<F> {
   const { assert!(size_of::<F>() == size_of::<usize>()) };
   let prologue = pick(Prologues::of(Abi::of(image)));
   // SAFETY: forwarded from the caller.
   match unsafe { image.hook_entry(target, prologue.pattern, prologue.len, detour) } {
      // SAFETY: the trampoline runs `target`'s displaced instructions, so it
      // has `F`'s ABI.
      Ok(trampoline) => Some(unsafe { std::mem::transmute_copy::<usize, F>(&trampoline) }),
      Err(err) => {
         log::warn!("{what}: {err}");
         None
      },
   }
}

/// Hooks an sret function `target` with `detour` (written in the x86-64
/// convention where the return slot is the first argument) and returns the
/// trampoline as `F`, wrapping both ends with arm64 sret thunks on macOS.
///
/// # Safety
///
/// Runs before Discord's threads reach `target`, `detour` has its x86-style
/// sret ABI, and `F` is its function pointer type.
pub(crate) unsafe fn hook_sret<F: Copy>(
   image: &Image<'static>,
   pick: fn(Prologues) -> Prologue,
   target: usize,
   detour: usize,
   what: &str,
) -> Option<F> {
   const { assert!(size_of::<F>() == size_of::<usize>()) };
   let prologue = pick(Prologues::of(Abi::of(image)));
   // SAFETY: forwarded from the caller.
   #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
   let hooked = unsafe { image.hook_sret_entry(target, prologue.pattern, prologue.len, detour) };
   // SAFETY: forwarded from the caller.
   #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
   let hooked = unsafe { image.hook_entry(target, prologue.pattern, prologue.len, detour) };
   let orig = match hooked {
      Ok(orig) => orig,
      Err(err) => {
         log::warn!("{what}: {err}");
         return None;
      },
   };
   // SAFETY: `orig` runs `target`'s displaced instructions with `F`'s ABI.
   Some(unsafe { std::mem::transmute_copy::<usize, F>(&orig) })
}

/// The target and its swapped gateway registry, once [`prepare`] hooked them.
static PREPARED: Mutex<Option<(Image<'static>, &'static GatewayRegistry)>> = Mutex::new(None);

/// Hooks Discord from `DllMain` on Windows or the constructor on Linux and
/// macOS, before its own code runs.
///
/// Desktop Phoenix settles on the access gate in its first frames and stops
/// reading the gateway registry and HTTP vtables once started, so hooks swapped
/// later from [`start`]'s thread never run. [`start`] picks up what this
/// hooked.
pub fn prepare() -> Result<(), Error> {
   phoenix_runtime::set_platform(&Desktop);
   let image = phoenix_runtime::target()?;
   open_access_gate(&image);
   open_notification_gate(&image);
   settings::install(&image);
   #[cfg(windows)]
   restart::install(&image);
   staff::prepare(&image);
   modal::install(&image);
   context_menu::install(&image);
   // Before accessories hooks `MessageRow::render`, whose prologue the header
   // locators check.
   let header = X86_CODE.then(|| headers::locate(&image));
   accessories::install(&image);
   members::install(&image);
   if let Some(header) = header {
      headers::install(&image, header);
      message::install(&image);
      #[cfg(target_arch = "x86_64")]
      counts::install(&image);
   } else {
      #[cfg(target_os = "macos")]
      headers::arm64::install(&image);
   }
   icons::install(&image);
   composer::install(&image);
   sidebar::install(&image);
   toolbar::install(&image);
   badges::install(&image);
   emoji::install(&image);
   sticker::install(&image);
   stream::install(&image);
   #[cfg(windows)]
   gpui_theme::install(&image);
   <os::Os as os::DesktopOs>::install(&image);
   let registry = phoenix_runtime::hook(&image);
   if registry.is_ok() {
      #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
      route_direct_calls(&image);
      discord::install(&image);
      gateway_send::install(&image);
      accessories::install_optimistic_delete(&image);
      ready::install(&image);
   }
   #[cfg(target_os = "macos")]
   message::writer::install(&image);
   // The indexes are tens of MB and nothing reads them after startup.
   phoenix_sigs::desktop::release_call_index();
   phoenix_hook::arm64::release_ref_index();
   *PREPARED.lock().unwrap_or_else(PoisonError::into_inner) = Some((image, registry?));
   Ok(())
}

/// Opens the access gate for testing Discord without the plugin runtime.
pub fn open_gate_only() -> Result<(), Error> {
   phoenix_runtime::set_platform(&Desktop);
   let image = phoenix_runtime::target()?;
   open_access_gate(&image);
   #[cfg(windows)]
   restart::install(&image);
   Ok(())
}

/// Starts phoenix inside Desktop Phoenix, on what [`prepare`] hooked.
pub fn start(home: PathBuf, bundled: Vec<Plugin>) -> Result<Started, Error> {
   #[cfg(target_os = "macos")]
   phoenix_runtime::update::adopt_staged(&home, &home.join("plugins"));
   let prepared = PREPARED
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .take();
   if let Some((image, registry)) = prepared {
      return phoenix_runtime::start_hooked(&Desktop, image, registry, home, bundled);
   }
   let image = phoenix_runtime::target()?;
   let registry = phoenix_runtime::hook(&image)?;
   discord::install(&image);
   gateway_send::install(&image);
   phoenix_runtime::start_hooked(&Desktop, image, registry, home, bundled)
}

/// Desktop Phoenix shows "This app isn't available for your account" from
/// `libdiscord_ops_surfaces::client_access::ClientAccessGate`, and blocks the
/// login on it. One function reads it (1 blocked, 2 no gate, also what a
/// missing value reads as), and the gate is only considered while it is not 2:
/// its small caller is `signed_in && access(..) != 2`. This makes it return 2.
/// Discord settles on the gate within its first frames, so the loader calls
/// this from `DllMain` or the constructor, before Discord's own code.
fn open_access_gate(image: &Image<'static>) {
   /// `mov al, 2; ret`
   const ALLOWED: [u8; 3] = [0xB0, 0x02, 0xC3];

   let found = if X86_CODE {
      phoenix_sigs::desktop::access_gate(image).map(|access| (access, &ALLOWED[..]))
   } else {
      close_enforced(image);
      keep_pages_over_frame(image);
      phoenix_sigs::macos::access_gate(image)
         .map(|access| (access, &phoenix_sigs::macos::NO_GATE[..]))
   };
   let (access, allowed) = match found {
      Ok(found) => found,
      Err(err) => {
         log::warn!("access gate: {err}, leaving it");
         return;
      },
   };
   // SAFETY: Discord's own code, written from `DllMain` or the constructor
   // before it runs.
   match unsafe { image.write_code(access, allowed) } {
      Ok(()) => log::info!("access gate: open"),
      Err(err) => log::error!("access gate: {err}"),
   }
}

/// Desktop Phoenix's `surfaces` notification provider claims every message
/// alert and returns it empty for a client it reads as gated, so the real alert
/// is never built and nothing reaches the OS; [`open_access_gate`]'s patch does
/// not reach this, since it reads the gate state from the store directly. This
/// forces its predicate to answer 0 ("not mine"), so the provider declines and
/// the planner's fallback builds the real alert, as it does on the official
/// app. `xor eax, eax; nop` replaces the `movzx eax, cl` that would otherwise
/// carry the "mine" answer into the function's return.
fn open_notification_gate(image: &Image<'static>) {
   /// `xor eax, eax; nop` in place of `movzx eax, cl`.
   const DECLINE: [u8; 3] = [0x31, 0xC0, 0x90];

   let gate = match phoenix_sigs::desktop::notification_gate(image) {
      Ok(gate) => gate,
      Err(err) => {
         log::warn!("notification gate: {err}, leaving it");
         return;
      },
   };
   // SAFETY: Discord's own code, written from `DllMain` or the constructor
   // before it runs.
   match unsafe { image.write_code(gate, &DECLINE) } {
      Ok(()) => log::info!("notification gate: open"),
      Err(err) => log::error!("notification gate: {err}"),
   }
}

/// Makes macOS's `client_access::enforced` answer false. `push_access` asks it
/// without the access function and drops every message alert for a gated
/// account, notifications and their sounds included.
fn close_enforced(image: &Image<'static>) {
   let enforced = phoenix_sigs::macos::access_read(image)
      .and_then(|read| phoenix_sigs::macos::access_enforced(image, read));
   // SAFETY: as for the access function in `open_access_gate`.
   match enforced.map(|at| unsafe { image.write_code(at, &phoenix_sigs::macos::NOT_ENFORCED) }) {
      Ok(Ok(())) => log::info!("access gate: not enforced, message alerts are on"),
      Ok(Err(err)) => log::error!("access gate: {err}"),
      Err(err) => log::warn!("access gate: {err}, message alerts stay off"),
   }
}

/// Keeps macOS embedded webviews above `GPUIView` so mouse clicks reach
/// interactive modals like hCaptcha (release builds ignore
/// `LIBDISCORD_MAC_PAGES_OVER_FRAME`).
fn keep_pages_over_frame(image: &Image<'static>) {
   let func = match phoenix_sigs::macos::pages_under_frame(image) {
      Ok(func) => func,
      Err(err) => {
         log::warn!("webview pages_under_frame: {err}, leaving it");
         return;
      },
   };
   // SAFETY: Discord's own code, written from the constructor before it runs.
   match unsafe { image.write_code(func, &phoenix_sigs::macos::PAGES_OVER_FRAME) } {
      Ok(()) => log::info!("webview: pages_under_frame disabled @ {func:#x}"),
      Err(err) => log::error!("webview pages_under_frame: {err}"),
   }
}

/// Hooks every gateway handler's entry directly on arm64: some hosts call a
/// handler directly past the registry (macOS deletes your own message that
/// way). Each stub passes its own trampoline in `x3` so events missing from the
/// registry still fall back to Discord's original handler.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn route_direct_calls(image: &Image<'static>) {
   let detour = phoenix_runtime::gateway::entry_detour_with_fallback();
   let handlers = phoenix_runtime::gateway::handlers();
   let mut hooked = 0;
   for &handler in &handlers {
      // SAFETY: runs from `prepare` before Discord's threads; the fallback
      // stub passes `trampoline` in `x3` and preserves `x0..=x2`, and the
      // registry is pointed at the trampoline before anything can call either.
      match unsafe { image.hook_entry_with_fallback(handler, detour) } {
         Ok(trampoline) => {
            phoenix_runtime::gateway::call_handler_through(handler, trampoline);
            hooked += 1;
         },
         Err(err) => log::warn!("desktop: gateway handler {handler:#x} not hooked: {err}"),
      }
   }
   log::info!(
      "desktop: {hooked} of {} gateway handlers hooked for direct calls",
      handlers.len()
   );
}

impl Platform for Desktop {
   fn send(&self, request: &Request) -> Result<Response, FetchError> {
      fetch::send(request)
   }

   fn query(&self, database: &Path, sql: &str, args: &[String]) -> Result<Rows, StoreError> {
      phoenix_runtime::store::sqlite(database, sql, args)
   }

   fn discord(
      &self,
      method: &str,
      path: &str,
      headers: Vec<(String, String)>,
      body: Vec<u8>,
   ) -> Result<Response, DiscordError> {
      discord::send(method, path, headers, body)
   }

   fn authorize(&self, request: &Authorization) -> Result<String, DiscordError> {
      discord::authorize(request)
   }

   fn init(&self, ctx: &Ctx<'_>) -> rquickjs::Result<()> {
      ctx.store_userdata(js::Desktop::default())
         .map_err(|err| rquickjs::Exception::throw_internal(ctx, &err.to_string()))?;
      Ok(())
   }

   fn api<'js>(
      &self,
      ctx: &Ctx<'js>,
      plugin: &str,
      api: &Object<'js>,
      messages: &Object<'js>,
   ) -> rquickjs::Result<()> {
      js::ui::desktop_patch_api(ctx, plugin, api, messages)
   }

   fn console<'js>(&self, ctx: &Ctx<'js>, phoenix: &Object<'js>) -> rquickjs::Result<()> {
      phoenix.set("native", js::native::object(ctx)?)
   }

   fn unload(&self, ctx: &Ctx<'_>, plugin: &str) {
      js::unload(ctx, plugin);
   }

   fn staff(&self, image: &'static Image<'static>) {
      staff::start(image);
   }

   fn gateway(&self, store: *mut c_void) {
      // SAFETY: every registry handler takes the store state first, and this
      // runs inside one.
      unsafe { staff::apply(store) };
   }

   fn started(&self, _first_run: bool, _plugins: &[String]) {
      let Some(state) = phoenix_runtime::state() else {
         return;
      };
      let _ = std::fs::create_dir_all(state.plugins_dir());
      // Any local process could reach the shell's `/eval` and the session, so
      // it only listens once DevTools is opened, and only for holders of this
      // start's token. `SUNBIRD_DEVTOOLS` starts it at launch, for `dev.ps1`.
      remote::require_token(&state.plugins_dir().with_file_name("debug-shell-token"));
      if std::env::var_os("SUNBIRD_DEVTOOLS").is_some() {
         start_shell();
      }
      phoenix_ui_desktop::start_tray(phoenix_ui_desktop::TrayConfig {
         devtools_url:     Arc::new(start_shell),
         plugins_dir:      state.plugins_dir(),
         on_reload_all:    Some(Arc::new(phoenix_runtime::reload_all)),
         on_check_updates: Some(Arc::new(phoenix_runtime::update::check_now)),
      });
      let ready_body = format!(
         "Open User Settings -> Sunbird, or press {} for DevTools",
         phoenix_ui_desktop::DEVTOOLS_SHORTCUT
      );
      phoenix_ui_desktop::notify("Sunbird ready", Some(&ready_body));
      phoenix_runtime::update::check();
   }

   fn refresh(&self) {
      modal::force_redraw();
   }

   fn toast(&self, message: &str) {
      phoenix_ui_desktop::toast(message);
   }

   fn notify(&self, notice: Notice<'_>) {
      match notice {
         Notice::UpdateAvailable(update) => {
            let mut parts = Vec::new();
            if let Some(version) = &update.loader {
               parts.push(format!("Sunbird {version} (restart to update)"));
            }
            if !update.plugins.is_empty() {
               parts.push(format!("plugins: {}", update.plugins.join(", ")));
            }
            let body = if parts.is_empty() {
               "Open Settings -> Sunbird".to_owned()
            } else {
               parts.join(" · ")
            };
            phoenix_ui_desktop::notify("Sunbird update available", Some(&body));
         },
         Notice::PluginsUpdated(names) if !names.is_empty() => {
            let body = format!("Reloaded: {}", names.join(", "));
            phoenix_ui_desktop::notify("Plugins updated", Some(&body));
         },
         Notice::PluginsUpdated(_) => {},
      }
   }

   #[cfg(target_os = "macos")]
   fn updates_loader(&self) -> bool {
      macos_loader_path().is_some()
   }

   #[cfg(target_os = "macos")]
   fn update_loader(&self, version: &str, update: &phoenix_runtime::update::Update) {
      update_macos_loader(version, update);
   }

   fn route(&self, request: &remote::Request) -> Option<remote::Reply> {
      let html = || {
         (
            "200 OK",
            "text/html; charset=utf-8",
            phoenix_ui_desktop::DASHBOARD_HTML.as_bytes().to_vec(),
         )
      };
      match (request.method.as_str(), request.path.as_str()) {
         ("GET", "/ui") => Some(html()),
         ("GET", "/") if request.accept.contains("text/html") => Some(html()),
         ("POST", "/ui/devtools") => {
            phoenix_ui_desktop::open_devtools();
            Some(remote::ok_json(&Done::Started))
         },
         ("POST", "/ui/choose") => Some(dialog(&request.body, false)),
         ("POST", "/ui/sheet") => Some(dialog(&request.body, true)),
         _ => None,
      }
   }

   fn routes(&self) -> &'static str {
      ", GET /ui, POST /ui/devtools, POST /ui/{choose,sheet}"
   }
}

/// Opens a native choose or sheet dialog for the dashboard and blocks this
/// request's thread until it is answered.
/// Starts the debug shell if it isn't running and returns the `DevTools` URL.
fn start_shell() -> String {
   remote::set_flag(true);
   remote::ensure_started();
   remote::dashboard_url()
}

fn dialog(body: &[u8], sheet: bool) -> remote::Reply {
   let Ok(request) = serde_json::from_slice::<DialogRequest>(body) else {
      return remote::err("400 Bad Request", "expected a JSON dialog request");
   };
   let options = request
      .options
      .unwrap_or_default()
      .into_iter()
      .map(|item| {
         match item {
            DialogItem::Label(label) => {
               modal::ChoiceOption {
                  label,
                  danger: false,
               }
            },
            DialogItem::Item { label, danger } => modal::ChoiceOption { label, danger },
         }
      })
      .collect::<Vec<_>>();
   let content = if sheet {
      request.text.map(|text| {
         modal::ModalSection::Code {
            title: None,
            text,
            monospace: request.monospace.unwrap_or_default(),
            highlight: request.highlight.unwrap_or_default(),
         }
      })
   } else {
      request
         .message
         .map(|text| modal::ModalSection::Text { title: None, text })
   };
   if content.is_none() && options.is_empty() {
      return remote::err(
         "400 Bad Request",
         if sheet {
            "a sheet needs text"
         } else {
            "a choose dialog needs a message or options"
         },
      );
   }
   let title = request.title.unwrap_or_else(|| "Sunbird".to_owned());
   let index = modal::ask(title, content, options, Duration::from_secs(120));
   remote::ok_json(&DialogAnswer { index })
}

#[cfg(target_os = "macos")]
fn macos_loader_path() -> Option<PathBuf> {
   let mut info = std::mem::MaybeUninit::<libc::Dl_info>::zeroed();
   // SAFETY: queries the Mach-O image that holds this function.
   let ok = unsafe { libc::dladdr(macos_loader_path as *const c_void, info.as_mut_ptr()) };
   if ok == 0 {
      return None;
   }
   // SAFETY: `dladdr` returned non-zero, so `info` is initialized.
   let info = unsafe { info.assume_init() };
   if info.dli_fname.is_null() {
      return None;
   }
   // SAFETY: `dli_fname` is a NUL-terminated path from dyld.
   let path = unsafe { std::ffi::CStr::from_ptr(info.dli_fname) }
      .to_str()
      .ok()?;
   let path = PathBuf::from(path);
   // `sunbird-macos.sh` writes `version` beside the dylib it installs, and a
   // dev build injected from `target/` has none, so updates leave it alone.
   (path.is_file() && path.with_file_name("version").is_file()).then_some(path)
}

#[cfg(target_os = "macos")]
fn update_macos_loader(version: &str, update: &phoenix_runtime::update::Update) {
   use phoenix_runtime::update;

   const ASSET: &str = "libphoenix-macos-arm64.dylib";

   let finish_err = |msg: String| {
      log::error!("loader update: {msg}");
      update::finish(Some(format!("Loader update failed: {msg}")));
      phoenix_ui_desktop::toast(&format!("Loader update failed: {msg}"));
   };

   let Some(dest) = macos_loader_path() else {
      finish_err("could not locate loaded libphoenix.dylib".to_owned());
      return;
   };
   let Some(dir) = dest.parent() else {
      finish_err("loaded dylib has no parent directory".to_owned());
      return;
   };

   update::set_status(Some(format!("Downloading Sunbird {version}...")));
   let url = format!("{}plugins/{ASSET}", update::ASSETS);
   let bytes = match phoenix_runtime::fetch::get(&url) {
      Ok(bytes) => bytes,
      Err(err) => {
         finish_err(err.to_string());
         return;
      },
   };
   if !bytes.starts_with(&[0xCF, 0xFA, 0xED, 0xFE]) {
      finish_err("downloaded dylib is not a 64-bit Mach-O binary".to_owned());
      return;
   }
   if let Err(err) = update::verify_loader(ASSET, version, &bytes, update) {
      finish_err(err);
      return;
   }

   let tmp = dir.join(format!("libphoenix.dylib.next.{}", std::process::id()));
   if let Err(err) = std::fs::write(&tmp, &bytes) {
      finish_err(format!("write temp dylib: {err}"));
      return;
   }
   let signed = std::process::Command::new("/usr/bin/codesign")
      .args(["--force", "--sign", "-"])
      .arg(&tmp)
      .status()
      .is_ok_and(|s| s.success());
   if !signed {
      let _ = std::fs::remove_file(&tmp);
      finish_err("codesign failed".to_owned());
      return;
   }
   if let Err(err) = std::fs::rename(&tmp, &dest) {
      let _ = std::fs::remove_file(&tmp);
      finish_err(format!("swap dylib: {err}"));
      return;
   }
   let _ = std::fs::write(dir.join("version"), format!("{version}\n"));

   let failed_plugins = update::stage_plugins(version, update);
   let msg = if failed_plugins.is_empty() {
      format!("Updated to Sunbird {version}. Restart Sunbird to apply.")
   } else {
      format!(
         "Updated loader to Sunbird {version}, but failed to stage {} plugin(s) ({}). Restart \
          Sunbird to apply.",
         failed_plugins.len(),
         failed_plugins.join("; ")
      )
   };
   update::finish(Some(msg.clone()));
   phoenix_ui_desktop::toast(&msg);
}
