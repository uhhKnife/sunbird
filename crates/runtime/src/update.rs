//! Tells the user when the site ships a newer Phoenix Unlock: a newer loader,
//! or plugin bundles that differ from the installed ones. The site publishes
//! both in `version.json` (`web/tools/bundle-plugins.ts`).
//!
//! Plugin updates download each changed `plugins/<name>.js`, verify its CRC-32
//! against `version.json` and hot-reload it. A loader update is the platform's
//! ([`crate::Platform::update_loader`]).

use std::{
   collections::BTreeMap,
   fs,
   path::Path,
   sync::{
      Mutex,
      MutexGuard,
      PoisonError,
   },
   thread,
};

use crate::{
   Notice,
   permissions::{
      Declared,
      Permissions,
   },
};
/// This build's version, `<UTC commit date>-<short hash>` (`build.rs`).
pub const VERSION: &str = env!("PHOENIX_VERSION");
pub const SITE: &str = "https://sunbird.tools/";
pub const ASSETS: &str = "https://assets.sunbird.tools/";

/// Where `bundle-plugins.ts` reads the version from the loader the site ships.
#[used]
static MARKER: &str = concat!("phoenix-version:", env!("PHOENIX_VERSION"), ";");

#[derive(serde::Deserialize)]
struct Site {
   loader:      String,
   #[serde(default)]
   loader_crcs: BTreeMap<String, u32>,
   plugins:     BTreeMap<String, u32>,
}

/// What the site has that this install lacks.
#[derive(Clone)]
pub struct Update {
   /// The site's version, when it is newer than [`VERSION`].
   pub loader:      Option<String>,
   /// Expected CRC-32 for each loader binary listed in `version.json`.
   pub loader_crcs: BTreeMap<String, u32>,
   /// Installed plugins whose code differs from the site's.
   pub plugins:     Vec<String>,
   /// Expected CRC-32 for each plugin in [`Self::plugins`].
   pub plugin_crcs: BTreeMap<String, u32>,
}

/// A plugin the site offers, as `plugins/index.json` lists it.
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct Listed {
   pub name:        String,
   pub description: String,
   #[serde(default)]
   pub warning:     Option<String>,
}

/// The site's plugin list, fetched when the install page first opens.
#[derive(Clone)]
pub enum Catalog {
   Unfetched,
   Loading,
   Loaded(Vec<Listed>),
   Failed(String),
}

static CATALOG: Mutex<Catalog> = Mutex::new(Catalog::Unfetched);
static FOUND: Mutex<Option<Update>> = Mutex::new(None);
static PROGRESS: Mutex<Progress> = Mutex::new(Progress::Idle);

/// What the one update slot is doing. Only a [`Slot`] leaves `Idle`.
enum Progress {
   Idle,
   Running(String),
   Finished(String),
}

/// The claim on the update slot. Dropping it releases the slot, with the line
/// [`Slot::finish`] left or none.
#[must_use]
pub struct Slot {
   result: Option<String>,
}

impl Slot {
   /// Shows `step` while the update runs.
   pub fn step(&self, step: impl Into<String>) {
      *progress() = Progress::Running(step.into());
      crate::refresh_settings();
   }

   /// Releases the slot with `result` shown.
   pub fn finish(mut self, result: Option<String>) {
      self.result = result;
   }
}

impl Drop for Slot {
   fn drop(&mut self) {
      *progress() = self
         .result
         .take()
         .map_or(Progress::Idle, Progress::Finished);
      crate::refresh_settings();
   }
}

fn progress() -> MutexGuard<'static, Progress> {
   PROGRESS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Claims the update slot showing `step`. `None` when an update already runs.
pub fn begin(step: impl Into<String>) -> Option<Slot> {
   let mut progress = progress();
   if matches!(*progress, Progress::Running(_)) {
      return None;
   }
   *progress = Progress::Running(step.into());
   drop(progress);
   crate::refresh_settings();
   Some(Slot { result: None })
}

/// The update the last check found, if any.
pub fn found() -> Option<Update> {
   FOUND.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

/// The step the running update shows, or the line the last one left.
#[must_use]
pub fn status() -> Option<String> {
   match &*progress() {
      Progress::Idle => None,
      Progress::Running(line) | Progress::Finished(line) => Some(line.clone()),
   }
}

/// Whether an update holds the slot.
#[must_use]
pub fn busy() -> bool {
   matches!(*progress(), Progress::Running(_))
}

pub fn catalog() -> Catalog {
   CATALOG
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .clone()
}

/// Fetches the site's plugin list in the background, unless it is loaded or
/// on its way. A failed fetch is retried on the next call.
pub fn fetch_catalog() {
   {
      let mut catalog = CATALOG.lock().unwrap_or_else(PoisonError::into_inner);
      if matches!(*catalog, Catalog::Loading | Catalog::Loaded(_)) {
         return;
      }
      *catalog = Catalog::Loading;
   }
   thread::spawn(|| {
      let fetched = crate::fetch::get(&format!("{ASSETS}plugins/index.json"))
         .map_err(|err| err.to_string())
         .and_then(|body| {
            serde_json::from_slice::<Vec<Listed>>(&body).map_err(|err| err.to_string())
         });
      *CATALOG.lock().unwrap_or_else(PoisonError::into_inner) = match fetched {
         Ok(listed) => Catalog::Loaded(listed),
         Err(err) => {
            log::info!("plugin list: {err}");
            Catalog::Failed(err)
         },
      };
      crate::refresh_settings();
   });
}

/// Installs a plugin the site lists. Site plugins can call API an older loader
/// lacks, so platforms with an in-app loader updater wait until the loader is
/// current.
pub fn install_listed(name: &str) -> Result<crate::installer::Installed, crate::Error> {
   let updates_loader = crate::platform().is_some_and(<dyn crate::Platform>::updates_loader);
   if updates_loader && let Some(version) = found().and_then(|update| update.loader) {
      return Err(crate::Error::LoaderOutdated { version });
   }
   crate::install(&format!("{ASSETS}plugins/{name}.js"))
}

/// Whether a plugin that needs loader `min_sunbird` is held back on this one.
/// Versions are `<UTC date>-<hash>`, which sort by date first as strings.
#[must_use]
pub fn outdated(min_sunbird: &str) -> bool {
   min_sunbird > VERSION
}

/// Asks the site what this install lacks, and remembers it for [`found`].
/// `None` means up to date.
fn query() -> Result<Option<Update>, String> {
   let body = crate::fetch::get(&format!("{ASSETS}version.json")).map_err(|err| err.to_string())?;
   let site =
      serde_json::from_slice::<Site>(&body).map_err(|err| format!("version.json: {err}"))?;
   let loader = (site.loader.as_str() > VERSION).then_some(site.loader);
   // Plugins come along with a loader update, so one tap brings both.
   let mut plugins = Vec::new();
   let mut plugin_crcs = BTreeMap::new();
   for plugin in crate::plugins() {
      if let Some(&crc) = site.plugins.get(&plugin.name)
         && crate::source(&plugin.name)
            .is_some_and(|source| crc32fast::hash(source.as_bytes()) != crc)
      {
         plugin_crcs.insert(plugin.name.clone(), crc);
         plugins.push(plugin.name);
      }
   }
   let update = (loader.is_some() || !plugins.is_empty()).then_some(Update {
      loader,
      loader_crcs: site.loader_crcs,
      plugins,
      plugin_crcs,
   });
   FOUND
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .clone_from(&update);
   crate::refresh_settings();
   Ok(update)
}

/// Asks the site in the background. Failures (offline) are only logged.
pub fn check() {
   thread::spawn(|| {
      let update = match query() {
         Ok(Some(update)) => update,
         Ok(None) => {
            log::info!("up to date ({VERSION})");
            return;
         },
         Err(err) => {
            log::info!("update check: {err}");
            return;
         },
      };
      log::info!(
         "update available: loader {:?}, plugins {:?}",
         update.loader,
         update.plugins
      );
      if let Some(platform) = crate::platform() {
         platform.notify(Notice::UpdateAvailable(&update));
      }
   });
}

/// Checks the site on demand for a user click, updating status and showing a
/// toast on completion.
pub fn check_now() {
   let Some(slot) = begin("Checking for updates...") else {
      log::info!("update check: already running");
      crate::toast("Update check already in progress...");
      return;
   };
   thread::spawn(move || {
      match query() {
         Ok(Some(update)) => {
            log::info!(
               "update available: loader {:?}, plugins {:?}",
               update.loader,
               update.plugins
            );
            drop(slot);
            if let Some(platform) = crate::platform() {
               platform.notify(Notice::UpdateAvailable(&update));
            }
         },
         Ok(None) => {
            log::info!("up to date ({VERSION})");
            slot.finish(Some(format!("Sunbird {VERSION} is up to date.")));
            crate::toast("Sunbird is up to date");
         },
         Err(err) => {
            log::info!("update check: {err}");
            let msg = format!("Update check failed: {err}");
            slot.finish(Some(msg.clone()));
            crate::toast(&msg);
         },
      }
   });
}

/// Checks the site again and applies what this install lacks.
///
/// Updates changed plugins over-the-air first (hot-reloading them live), then
/// runs the in-app APK self-updater if a newer loader is available.
pub fn apply() {
   let Some(slot) = begin("Checking for updates...") else {
      log::info!("update apply: already running");
      crate::toast("Update already in progress...");
      return;
   };
   thread::spawn(move || {
      // The last check ran when Discord started, and the site may have shipped
      // since, so what it found can be out of date by the time this runs.
      let update = query().unwrap_or_else(|err| {
         log::info!("update apply: {err}, using the last check");
         found()
      });
      let Some(update) = update else {
         log::info!("update apply: up to date ({VERSION})");
         drop(slot);
         crate::toast("Sunbird is up to date");
         return;
      };
      // The site's plugins are built against its loader and can call API this
      // one lacks, so with a loader update they wait in `plugins.next/` for it.
      if let Some(version) = &update.loader
         && let Some(platform) = crate::platform()
      {
         if platform.updates_loader() {
            platform.update_loader(slot, version, &update);
            return;
         }
         if update.plugins.is_empty() {
            let msg = format!("Sunbird {version} is available — restart Sunbird to update.");
            slot.finish(Some(msg.clone()));
            crate::toast(&msg);
            return;
         }
      }
      let mut updated_plugins = Vec::new();
      let mut failed = Vec::new();
      if !update.plugins.is_empty() {
         slot.step(format!(
            "Updating {} plugin{}...",
            update.plugins.len(),
            if update.plugins.len() == 1 { "" } else { "s" }
         ));
         for name in &update.plugins {
            let expected_crc = update.plugin_crcs.get(name).copied();
            match update_plugin(name, expected_crc) {
               Ok(()) => {
                  log::info!("ota updated plugin {name}");
                  updated_plugins.push(name.clone());
               },
               Err(err) => {
                  log::error!("ota update {name} failed: {err}");
                  failed.push(format!("{name}: {err}"));
               },
            }
         }
         // Drop successfully updated plugins from FOUND.
         {
            let mut guard = FOUND.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(pending) = guard.as_mut() {
               pending
                  .plugins
                  .retain(|name| !updated_plugins.contains(name));
               pending
                  .plugin_crcs
                  .retain(|name, _| !updated_plugins.contains(name));
               if pending.loader.is_none() && pending.plugins.is_empty() {
                  *guard = None;
               }
            }
         }
      }

      // A failed plugin used to go unreported whenever the loader update below
      // still had to run, since only `update.loader.is_none()` printed it.
      // The slot is released either way, and the failure keeps its line.
      if failed.is_empty() {
         drop(slot);
      } else {
         let msg = format!("Plugin update failed: {}", failed.join("; "));
         log::error!("{msg}");
         slot.finish(Some(msg.clone()));
         crate::toast(&msg);
      }
      if !updated_plugins.is_empty()
         && let Some(platform) = crate::platform()
      {
         platform.notify(Notice::PluginsUpdated(&updated_plugins));
      }
   });
}

fn update_plugin(name: &str, expected_crc: Option<u32>) -> Result<(), String> {
   let source = download_plugin(name, expected_crc)?;
   if let Some(min) = crate::Header::from(source.as_str()).min_sunbird
      && outdated(&min)
   {
      return Err(format!("needs Sunbird {min}, update Phoenix Unlock first"));
   }
   same_reach(name, &source)?;
   crate::save_source(name, source).map_err(|err| err.to_string())
}

/// Refuses an update that declares more than the running copy and the
/// bundled one, since the user agreed only to what those reach. Copies from
/// before permission lines declare nothing, and would otherwise never update.
fn same_reach(name: &str, source: &str) -> Result<(), String> {
   let Some(running) = crate::source(name) else {
      return Ok(());
   };
   let newer = source
      .parse::<Permissions>()
      .map_err(|err| err.to_string())?;
   let widened = |copy: &str| {
      copy
         .parse::<Permissions>()
         .unwrap_or_else(|_| Permissions::Declared(Declared::default()))
         .widened(&newer)
   };
   let mut added = widened(&running);
   if let Some(bundled) = crate::bundled_source(name) {
      let past_bundled = widened(&bundled);
      added.retain(|grant| past_bundled.contains(grant));
   }
   if added.is_empty() {
      return Ok(());
   }
   Err(format!(
      "the update asks for {}, remove it and install it again from the plugin list to allow that",
      added.join(", ")
   ))
}

/// Verifies a downloaded loader binary against its exact embedded version
/// marker and the CRC-32 published for `asset` in `version.json`.
pub fn verify_loader(
   asset: &str,
   version: &str,
   bytes: &[u8],
   update: &Update,
) -> Result<(), String> {
   let marker = format!("phoenix-version:{version};");
   if !bytes
      .windows(marker.len())
      .any(|window| window == marker.as_bytes())
   {
      return Err(format!("missing version marker for {version}"));
   }
   let expected = update
      .loader_crcs
      .get(asset)
      .copied()
      .ok_or_else(|| format!("missing CRC-32 for {asset} in version.json"))?;
   let actual = crc32fast::hash(bytes);
   if actual != expected {
      return Err(format!(
         "CRC mismatch for {asset} (got {actual:#x}, expected {expected:#x})"
      ));
   }
   Ok(())
}

/// The site's `plugins/<name>.js`, checked against its CRC-32.
pub fn download_plugin(name: &str, expected_crc: Option<u32>) -> Result<String, String> {
   let url = format!("{ASSETS}plugins/{name}.js");
   let bytes = crate::fetch::get(&url).map_err(|err| format!("fetch: {err}"))?;
   if let Some(expected) = expected_crc {
      let actual = crc32fast::hash(&bytes);
      if actual != expected {
         return Err(format!(
            "CRC mismatch (got {actual:#x}, expected {expected:#x})"
         ));
      }
   }
   String::from_utf8(bytes).map_err(|err| format!("invalid UTF-8: {err}"))
}

/// Where plugins for a loader not installed yet wait, with that loader's
/// version in [`STAGED_FOR`].
const STAGED: &str = "plugins.next";
const STAGED_FOR: &str = "loader";

/// Downloads `update`'s plugins into [`STAGED`] for loader `version`, and
/// returns the ones that failed. A failed one stays as it is, and the next
/// check offers it again.
#[must_use]
pub fn stage_plugins(version: &str, update: &Update) -> Vec<String> {
   let Some(state) = crate::state() else {
      return vec!["runtime not started".to_owned()];
   };
   let dir = state.home.join(STAGED);
   let _ = fs::remove_dir_all(&dir);
   if let Err(err) = fs::create_dir_all(&dir) {
      log::error!("staging plugins: {}: {err}", dir.display());
      return vec![format!("create {}: {err}", dir.display())];
   }
   let mut failed = Vec::new();
   for name in &update.plugins {
      let staged =
         download_plugin(name, update.plugin_crcs.get(name).copied()).and_then(|source| {
            same_reach(name, &source)?;
            fs::write(dir.join(format!("{name}.js")), source).map_err(|err| err.to_string())
         });
      match staged {
         Ok(()) => log::info!("staged plugin {name} for {version}"),
         Err(err) => {
            log::error!("staging {name} failed: {err}");
            failed.push(format!("{name}: {err}"));
         },
      }
   }
   if let Err(err) = fs::write(dir.join(STAGED_FOR), version) {
      log::error!("staging plugins: {err}");
      failed.push(format!("write stage marker: {err}"));
   }
   failed
}

/// Moves the plugins staged for this loader, or an older one, into `plugins`.
/// Plugins staged for a newer loader, whose install was not finished, wait.
pub fn adopt_staged(home: &Path, plugins: &Path) {
   let dir = home.join(STAGED);
   let Ok(version) = fs::read_to_string(dir.join(STAGED_FOR)) else {
      return;
   };
   if version.trim() > VERSION {
      return;
   }
   if let Err(err) = fs::create_dir_all(plugins) {
      log::error!("staged plugins: {}: {err}", plugins.display());
      return;
   }
   for entry in fs::read_dir(&dir).into_iter().flatten().flatten() {
      let path = entry.path();
      if path.extension().is_some_and(|extension| extension == "js")
         && let Some(name) = path.file_name()
         && let Err(err) = fs::rename(&path, plugins.join(name))
      {
         log::error!("staged plugin {}: {err}", path.display());
      }
   }
   let _ = fs::remove_dir_all(&dir);
   log::info!("moved in the plugins staged for {}", version.trim());
}
