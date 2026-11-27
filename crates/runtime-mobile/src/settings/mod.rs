//! A "Sunbird" row in Discord's Settings that opens phoenix's own
//! pages.
//!
//! Phoenix builds its UI as a stream of UI-op batches from Rust to Java. This
//! module rewrites those batches to splice in nodes built from Phoenix's own
//! layouts, and answers view events on them. Injected nodes use ids from
//! `0x5000_0000`, far above the counter Rust allocates from.

mod actions;
mod batch;
mod code;
mod console;
mod pages;
mod plugin;
mod render;
mod rows;
mod theme;
mod tree;

use std::{
   collections::{
      HashMap,
      HashSet,
   },
   sync::{
      LazyLock,
      Mutex,
      MutexGuard,
      OnceLock,
      PoisonError,
      atomic::{
         AtomicBool,
         Ordering,
      },
      mpsc::{
         self,
         Sender,
      },
   },
   thread,
};

use phoenix_runtime::PluginInfo;
use phoenix_ui_mobile::{
   Op,
   Props,
   encode,
};

use crate::{
   bridge::{
      self,
      Action,
      Sink,
   },
   settings::{
      actions::act,
      batch::{
         filter_dispatch,
         rewrite_ops,
      },
      tree::{
         SlotPool,
         Tree,
      },
   },
};

const FIRST_ID: i32 = 0x5000_0000;
/// The host drops motion slots at or above 65536, and Rust counts its own up
/// from 0, so phoenix takes them downward from the top.
const SLOT_END: i32 = 1 << 16;
/// The Settings row and the page it opens.
const TITLE: &str = "Sunbird";
const ICON_PLUGIN: &str = "res://ic_mana_puzzle_piece_plus";
const ICON_CHECK: &str = "res://ic_mana_checkmark_large";
const ICON_RELOAD: &str = "res://ic_mana_puzzle_piece_retry";
const ICON_UNINSTALL: &str = "res://ic_mana_puzzle_piece_minus";
const ICON_CONSOLE: &str = "res://ic_mana_angle_brackets";
const ICON_FILE: &str = "res://ic_mana_image_file_up";
/// Plugins are named by their index in [`phoenix_runtime::plugins`] as of the
/// last render, which every install follows with a fresh one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Press {
   OpenMain,
   OpenConsole,
   OpenInstall,
   OpenPlugin(usize),
   /// A plugin's code page, and saving what it holds.
   EditCode(usize),
   SaveCode(usize),
   PickFile,
   /// Installs or uninstalls a plugin the site lists, by its index in
   /// [`phoenix_runtime::update::catalog`].
   Listed(usize),
   Toggle(usize),
   Reload(usize),
   Uninstall(usize),
   /// A plugin's switch or button, by its index in [`PluginInfo::settings`].
   Setting(usize, usize),
   /// Option `option` of a plugin's select setting.
   Choose(usize, usize, usize),
   /// Apply the pending update in-app (OTA plugins / APK self-updater).
   ApplyUpdate,
   /// The site, to get the update [`crate::update`] found.
   OpenSite,
   ToggleStaff,
   ToggleRemoteShell,
   Back,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PageKind {
   Main,
   Console,
   Install,
   Plugin(usize),
   Code(usize),
}

/// What the UI thread hands to the worker. UI ops must not be sent from the
/// main thread, where Rust may hold the UI lock while it waits on Java.
enum Job {
   Press(Press),
   NavigateTo(usize),
   /// A text field's contents after an edit.
   Draft(Field, String),
   Submit(Field),
   Log,
   /// The file picker's answer.
   Picked(crate::picker::Picked),
   /// Something the open pages show changed.
   Refresh,
   /// Phoenix redrawn Settings for another light/dark theme.
   ThemeChanged,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Field {
   Eval,
   Install,
   /// A text or number setting, indexed like [`Press::Setting`].
   Setting(usize, usize),
   /// A plugin's code, by its index in [`phoenix_runtime::plugins`].
   Code(usize),
}

/// Nodes updated in place, so typing is not interrupted.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
   Input(Field),
   Log,
}

/// The "Sunbird" row in the Settings list.
struct Entry {
   root: i32,
   ids:  Vec<i32>,
}

struct Page {
   root:     i32,
   ids:      Vec<i32>,
   kind:     PageKind,
   content:  i32,
   sections: Vec<i32>,
   slots:    Vec<(i32, Slot)>,
   /// The built sections, to update in place when a rerender keeps their shape.
   trees:    Vec<Tree>,
}

/// The open Settings screen and what phoenix added to it.
struct Screen {
   list:       i32,
   /// Rust's own rows in the list and pages on the navigator, kept current
   /// from its batches.
   rust_rows:  Option<Vec<i32>>,
   search:     Option<i32>,
   navigator:  Option<i32>,
   rust_pages: Option<Vec<i32>>,
   header:     Option<Props>,
   entry:      Option<Entry>,
   stack:      Vec<Page>,
}

struct Settings {
   next_id:        i32,
   slots:          SlotPool,
   /// Motion words for nodes built since the last batch went out. They run
   /// after the batch attaches those nodes.
   motion:         Vec<i32>,
   navigators:     HashSet<i32>,
   screen:         Option<Screen>,
   handlers:       HashMap<i32, Press>,
   plugins:        Vec<PluginInfo>,
   drafts:         HashMap<Field, String>,
   /// The line nodes in each console log box, replaced on every refresh.
   log_rows:       HashMap<i32, Vec<i32>>,
   /// A counter for `forceValue`, which the host applies when it changes.
   force_seq:      i64,
   /// What the last install did, shown on the install page.
   install_status: Option<(String, i64)>,
}

static SETTINGS: LazyLock<Mutex<Settings>> = LazyLock::new(|| {
   Mutex::new(Settings {
      next_id:        FIRST_ID,
      slots:          SlotPool {
         next:  SLOT_END,
         free:  Vec::new(),
         owned: HashMap::new(),
      },
      motion:         Vec::new(),
      navigators:     HashSet::new(),
      screen:         None,
      handlers:       HashMap::new(),
      plugins:        Vec::new(),
      drafts:         HashMap::new(),
      log_rows:       HashMap::new(),
      force_seq:      1 << 40,
      install_status: None,
   })
});

static WORKER: OnceLock<Sender<Job>> = OnceLock::new();
/// Set while a [`Job::Log`] is queued, so a burst of lines costs one update.
static LOG_QUEUED: AtomicBool = AtomicBool::new(false);

fn settings() -> MutexGuard<'static, Settings> {
   SETTINGS.lock().unwrap_or_else(PoisonError::into_inner)
}

struct SettingsSink;

impl Sink for SettingsSink {
   fn ops(&self, batch: &[u8]) -> Action {
      rewrite_ops(batch)
   }

   fn dispatch(&self, frame: &[u8]) -> Action {
      filter_dispatch(frame)
   }
}

/// Hooks the UI bridge and starts the worker that answers presses.
pub fn start() {
   let (sender, receiver) = mpsc::channel::<Job>();
   if WORKER.set(sender).is_err() {
      log::warn!("settings: already started");
      return;
   }
   bridge::install(Box::new(SettingsSink));
   thread::spawn(move || {
      for job in receiver {
         act(&job);
         let plugins = matches!(
            job,
            Job::Press(_) | Job::Submit(_) | Job::Picked(_) | Job::Refresh
         )
         .then(phoenix_runtime::plugins);
         let ops = {
            let mut state = settings();
            if let Some(plugins) = plugins {
               let old = state
                  .plugins
                  .iter()
                  .map(|plugin| plugin.name.clone())
                  .collect::<Vec<_>>();
               state.plugins = plugins;
               let names = state
                  .plugins
                  .iter()
                  .map(|plugin| plugin.name.clone())
                  .collect::<Vec<_>>();
               state.drafts.retain(|field, _| {
                  match *field {
                     Field::Eval | Field::Install => true,
                     Field::Setting(index, _) | Field::Code(index) => {
                        old.get(index)
                           .is_some_and(|name| names.get(index).is_some_and(|new| new == name))
                     },
                  }
               });
            }
            let mut ops = state.run(job);
            if !state.motion.is_empty() {
               ops.push(Op::Motion {
                  words: std::mem::take(&mut state.motion),
               });
            }
            ops
         };
         if !ops.is_empty() && !bridge::apply_ops(&encode(&ops)) {
            log::warn!("settings: the UI update did not apply");
         }
      }
   });
   phoenix_runtime::update::check();
}

/// Rebuilds the open pages, for state that changed outside them.
pub fn refresh() {
   if let Some(worker) = WORKER.get() {
      let _ = worker.send(Job::Refresh);
   }
}

/// Refreshes the console page's log, if one is open.
pub fn log_changed() {
   if LOG_QUEUED.swap(true, Ordering::Relaxed) {
      return;
   }
   if let Some(worker) = WORKER.get()
      && worker.send(Job::Log).is_err()
   {
      LOG_QUEUED.store(false, Ordering::Relaxed);
   }
}

/// Hands the file picker's answer to the worker.
pub fn picked(picked: crate::picker::Picked) {
   if let Some(worker) = WORKER.get()
      && worker.send(Job::Picked(picked)).is_err()
   {
      log::warn!("settings: the worker stopped");
   }
}
