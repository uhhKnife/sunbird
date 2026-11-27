//! Keyboard shortcuts for `phoenix.ui.addShortcut`. Discord's UI thread only
//! checks the pressed key against what plugins registered and hands a match to
//! a worker, which runs the handlers, so the window never waits for the
//! plugin engine.

use std::sync::{
   Mutex,
   OnceLock,
   PoisonError,
   mpsc,
};

use phoenix_ui_desktop::Shortcut;

/// The keys plugins registered, each with how many handlers hold it.
static KEYS: Mutex<Vec<(Shortcut, usize)>> = Mutex::new(Vec::new());
static WORKER: OnceLock<mpsc::Sender<Shortcut>> = OnceLock::new();

/// Starts taking `shortcut` from Discord, until the matching [`release`].
pub fn hold(shortcut: Shortcut) {
   phoenix_ui_desktop::set_shortcut_handler(take);
   let mut keys = KEYS.lock().unwrap_or_else(PoisonError::into_inner);
   match keys.iter_mut().find(|(key, _)| *key == shortcut) {
      Some((_, holders)) => *holders += 1,
      None => keys.push((shortcut, 1)),
   }
}

/// Leaves `shortcut` to Discord again once no handler holds it.
pub fn release(shortcut: Shortcut) {
   let mut keys = KEYS.lock().unwrap_or_else(PoisonError::into_inner);
   if let Some((_, holders)) = keys.iter_mut().find(|(key, _)| *key == shortcut) {
      *holders = holders.saturating_sub(1);
   }
   keys.retain(|&(_, holders)| holders > 0);
}

/// On Discord's UI thread: whether a plugin holds `shortcut`, queueing its
/// handlers when one does.
fn take(shortcut: Shortcut) -> bool {
   let held = KEYS
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .iter()
      .any(|&(key, _)| key == shortcut);
   held && worker().send(shortcut).is_ok()
}

fn worker() -> &'static mpsc::Sender<Shortcut> {
   WORKER.get_or_init(|| {
      let (tx, rx) = mpsc::channel::<Shortcut>();
      let _ = std::thread::Builder::new()
         .name("sunbird-shortcuts".to_owned())
         .spawn(move || {
            while let Ok(shortcut) = rx.recv() {
               if let Some(engine) = phoenix_runtime::engine() {
                  crate::js::ui::run_shortcut(&engine, shortcut);
               }
            }
         });
      tx
   })
}
