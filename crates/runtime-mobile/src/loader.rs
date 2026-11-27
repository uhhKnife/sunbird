//! Updates the loader in-app. The site's plugins are built against its loader,
//! so they wait in `plugins.next/` while the new loader,
//! `plugins/libphoenix-<abi>.so`, is swapped into the installed APK with
//! [`patcher::swap_loader`], signed again and handed to Android's installer
//! through Discord's own `FileProvider`. The new loader moves the staged
//! plugins in before it loads any. An install from separate splits cannot
//! update from one APK, so it opens the site instead.

use std::{
   fs::{
      self,
      File,
   },
   io::{
      BufWriter,
      Write,
   },
   path::Path,
   thread,
};

use memchr::memmem;
use phoenix_runtime::update::{
   self,
   Slot,
   Update,
};

/// Where the signed update waits for Android's installer, under the app's
/// `files` directory, which Discord's `FileProvider` shares.
const UPDATE_APK: &str = "phoenix-update.apk";

const LOADER_ASSET: &str = if cfg!(target_arch = "x86_64") {
   "plugins/libphoenix-x86_64.so"
} else if cfg!(target_arch = "arm") {
   "plugins/libphoenix-armv7.so"
} else {
   "plugins/libphoenix-arm64.so"
};

/// Stages `update`'s plugins for loader `version`, then installs it.
pub fn install(slot: Slot, version: &str, update: &Update) {
   slot.step("Downloading plugins...");
   let _ = update::stage_plugins(version, update);
   run_loader_self_update(slot);
}

/// Runs the in-app loader self-update directly against the site's current
/// `libphoenix-*.so` (also exposed to the gated localhost debug shell).
pub fn self_update_from_site() {
   let Some(slot) = update::begin("Downloading loader...") else {
      log::info!("self-update: already running");
      return;
   };
   thread::spawn(move || run_loader_self_update(slot));
}

fn run_loader_self_update(slot: Slot) {
   match self_update(&slot) {
      Ok(()) => slot.finish(None),
      Err(message) => {
         log::error!("self-update: {message}");
         slot.finish(Some(message.clone()));
         let _ = crate::picker::toast(&message);
      },
   }
}

fn self_update(slot: &Slot) -> Result<(), String> {
   slot.step("Downloading loader...");
   let _ = crate::picker::toast("Downloading Phoenix Unlock update...");

   let url = format!("{}{LOADER_ASSET}", update::ASSETS);
   let bytes =
      phoenix_runtime::fetch::get(&url).map_err(|err| format!("Download failed: {err}"))?;
   if !bytes.starts_with(b"\x7fELF") || memmem::find(&bytes, b"phoenix-version:").is_none() {
      return Err("Downloaded loader is invalid".to_owned());
   }

   let loader = patcher::Library::new(patcher::LOADER, bytes)
      .map_err(|err| format!("Downloaded loader is invalid: {err}"))?;
   let base = crate::host::base_apk().map_err(|err| format!("Self-update failed: {err}"))?;
   if installed_from_splits(&base) {
      let _ = crate::picker::open(update::SITE);
      return Err("Split APK install, update from the site".to_owned());
   }

   slot.step("Signing the update...");
   let state = phoenix_runtime::state().ok_or("Self-update failed: phoenix has not started")?;
   let files = crate::install::files_dir().unwrap_or_else(|| state.files_dir());
   fs::create_dir_all(&files)
      .map_err(|err| format!("Self-update failed: {}: {err}", files.display()))?;
   let path = files.join(UPDATE_APK);
   write_update(&base, &loader, &path).map_err(|err| format!("Self-update failed: {err}"))?;
   slot.step("Opening Android's installer...");
   crate::install::open(&path).map_err(|err| format!("Self-update failed: {err}"))
}

/// Whether the app runs from split APKs, which sit next to `base`.
fn installed_from_splits(base: &str) -> bool {
   Path::new(base)
      .parent()
      .and_then(|dir| fs::read_dir(dir).ok())
      .is_some_and(|entries| {
         entries.flatten().any(|entry| {
            entry.file_name().to_str().is_some_and(|name| {
               name.starts_with("split_")
                  && Path::new(name)
                     .extension()
                     .is_some_and(|extension| extension.eq_ignore_ascii_case("apk"))
            })
         })
      })
}

/// Writes `base` with `loader` swapped in and signed to `path`.
fn write_update(base: &str, loader: &patcher::Library, path: &Path) -> Result<(), String> {
   let map = crate::host::Map::open(base).map_err(|err| format!("{base}: {err}"))?;
   let apk = patcher::swap_loader(map.bytes(), loader).map_err(|err| err.to_string())?;
   let mut file =
      BufWriter::new(File::create(path).map_err(|err| format!("{}: {err}", path.display()))?);
   for part in apk.parts() {
      file.write_all(part).map_err(|err| err.to_string())?;
   }
   file.flush().map_err(|err| err.to_string())
}

/// Deletes an update Android's installer has had its chance at, since it is as
/// big as the app.
pub fn forget_update(files: &Path) {
   let _ = fs::remove_file(files.join(UPDATE_APK));
   if let Some(real) = crate::install::files_dir()
      && real != files
   {
      let _ = fs::remove_file(real.join(UPDATE_APK));
   }
}
