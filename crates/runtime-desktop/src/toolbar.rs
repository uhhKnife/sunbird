//! Plugin buttons in the channel header toolbar, for
//! `phoenix.ui.addHeaderButton`.
//!
//! The toolbar's member list button is built by Discord's own icon button
//! builder and added with `append`. The builder's call hands [`button_detour`]
//! the `App`, and once `append` adds the member list button,
//! [`append_detour`] builds each plugin button the same way, with a click
//! handler of ours, and adds it after. The toolbar has no member list button
//! where Discord shows no member list, and plugin buttons follow it there.

use std::{
   cell::Cell,
   ffi::c_void,
   ptr,
   sync::{
      OnceLock,
      PoisonError,
      RwLock,
      atomic::{
         AtomicBool,
         AtomicUsize,
         Ordering,
      },
      mpsc,
   },
};

use phoenix_hook::image::Image;
use phoenix_sigs::desktop::{
   self,
   layout,
};

use crate::gpui::{
   self,
   RcFnVtbl,
   Scratch,
   SharedString,
};

/// `button(out, id, id_len, icon, tooltip, selected, _, cx) -> out`.
type ButtonFn = unsafe extern "C" fn(
   *mut u8,
   *const u8,
   usize,
   u32,
   *mut SharedString,
   u8,
   u8,
   *mut c_void,
) -> *mut u8;
/// `append(out, &mut toolbar, &mut button) -> out`.
type AppendFn = unsafe extern "C" fn(*mut u8, *mut u8, *mut u8) -> *mut u8;

/// A plugin's header button, as drawn.
#[derive(Clone)]
pub struct HeaderButton {
   pub id:       u64,
   pub icon:     u16,
   pub label:    String,
   pub priority: i32,
   /// Element id, `sunbird-header-{id}`.
   element:      &'static str,
}

static BUTTON: OnceLock<ButtonFn> = OnceLock::new();
static APPEND: OnceLock<AppendFn> = OnceLock::new();
static ON_CLICK: AtomicUsize = AtomicUsize::new(0);
static TOOLBAR_SIZE: AtomicUsize = AtomicUsize::new(0);
static READY: AtomicBool = AtomicBool::new(false);
static BUTTONS: RwLock<Vec<HeaderButton>> = RwLock::new(Vec::new());
static WORKER: OnceLock<mpsc::Sender<u64>> = OnceLock::new();

thread_local! {
   /// The `App` the member list button was built with, until it is added.
   static APP: Cell<usize> = const { Cell::new(0) };
}

static CLICK_VTBL: RcFnVtbl = RcFnVtbl {
   drop_in_place: ptr::null(),
   size:          size_of::<u64>(),
   align:         align_of::<u64>(),
   call_once:     on_click as *const c_void,
   call_mut:      on_click as *const c_void,
   call:          on_click as *const c_void,
   extra:         ptr::null(),
};

/// Hooks the member list button's builder and append calls from
/// [`crate::prepare`], before Discord's threads run.
pub fn install(image: &Image<'static>) {
   if !cfg!(all(target_os = "windows", target_arch = "x86_64")) {
      return;
   }
   let found = match desktop::channel_toolbar(image) {
      Ok(found) => found,
      Err(err) => {
         log::warn!("header buttons: {err}, none are drawn");
         return;
      },
   };
   ON_CLICK.store(found.on_click, Ordering::Release);
   TOOLBAR_SIZE.store(found.toolbar_size, Ordering::Release);
   let hooked = hook(
      image,
      found.button_site,
      button_detour as *const () as usize,
      |target| {
         // SAFETY: the call's own target, the toolbar icon button builder.
         let _ = BUTTON.set(unsafe { std::mem::transmute::<usize, ButtonFn>(target) });
      },
   ) && hook(
      image,
      found.append_site,
      append_detour as *const () as usize,
      |target| {
         // SAFETY: the call's own target, the toolbar's append.
         let _ = APPEND.set(unsafe { std::mem::transmute::<usize, AppendFn>(target) });
      },
   );
   READY.store(hooked, Ordering::Release);
}

/// Points the call at `site` to `detour` and hands `store` its old target.
fn hook(image: &Image<'static>, site: usize, detour: usize, store: impl FnOnce(usize)) -> bool {
   // SAFETY: runs from `prepare` before Discord's threads; each detour takes
   // its callee's exact arguments, so the island adds nothing, and waits for
   // `store` before it calls the original.
   match unsafe { image.hook_call(site, &[], detour) } {
      Ok(target) => {
         store(target);
         log::info!("header buttons: hooked @ {site:#x}");
         true
      },
      Err(err) => {
         log::warn!("header buttons: hook @ {site:#x} failed: {err}");
         false
      },
   }
}

/// Whether header buttons can be drawn on this build.
pub fn ready() -> bool {
   READY.load(Ordering::Acquire)
}

/// Draws `id`'s button with `icon` and `label`, or changes it.
pub fn set(id: u64, icon: u16, label: String, priority: i32) {
   let mut buttons = BUTTONS.write().unwrap_or_else(PoisonError::into_inner);
   match buttons.iter_mut().find(|button| button.id == id) {
      Some(button) => {
         button.icon = icon;
         button.label = label;
         button.priority = priority;
      },
      None => {
         buttons.push(HeaderButton {
            id,
            icon,
            label,
            priority,
            element: gpui::intern_str(&format!("sunbird-header-{id}")),
         });
      },
   }
   buttons.sort_by_key(|button| button.priority);
   drop(buttons);
   crate::accessories::invalidate_discord_windows();
}

/// The button `id` draws, if any.
pub fn get(id: u64) -> Option<HeaderButton> {
   BUTTONS
      .read()
      .unwrap_or_else(PoisonError::into_inner)
      .iter()
      .find(|button| button.id == id)
      .cloned()
}

/// Stops drawing `id`'s button.
pub fn remove(id: u64) {
   BUTTONS
      .write()
      .unwrap_or_else(PoisonError::into_inner)
      .retain(|button| button.id != id);
   crate::accessories::invalidate_discord_windows();
}

unsafe extern "C" fn button_detour(
   out: *mut u8,
   id: *const u8,
   id_len: usize,
   icon: u32,
   tooltip: *mut SharedString,
   selected: u8,
   flag: u8,
   cx: *mut c_void,
) -> *mut u8 {
   APP.set(cx as usize);
   let button = *BUTTON.wait();
   // SAFETY: forwards the builder's own arguments.
   unsafe { button(out, id, id_len, icon, tooltip, selected, flag, cx) }
}

unsafe extern "C" fn append_detour(out: *mut u8, toolbar: *mut u8, button: *mut u8) -> *mut u8 {
   let append = *APPEND.wait();
   // SAFETY: forwards the append's own arguments.
   let toolbar = unsafe { append(out, toolbar, button) };
   let cx = APP.replace(0);
   if cx == 0 || toolbar.is_null() || !ready() {
      return toolbar;
   }
   let buttons = BUTTONS
      .read()
      .unwrap_or_else(PoisonError::into_inner)
      .clone();
   for button in &buttons {
      let _ = std::panic::catch_unwind(|| add(toolbar, button, cx as *mut c_void));
   }
   toolbar
}

/// Builds `button` like the member list button and adds it to `toolbar`,
/// which `append` pushes into in place before moving it to a separate return
/// slot.
fn add(toolbar: *mut u8, button: &HeaderButton, cx: *mut c_void) {
   let (Some(build), Some(append)) = (BUTTON.get(), APPEND.get()) else {
      return;
   };
   let on_click = ON_CLICK.load(Ordering::Acquire);
   let mut raw = Scratch::<{ layout::SCRATCH_CAP }>::zeroed();
   let mut out = Scratch::<{ layout::SCRATCH_CAP }>::zeroed();
   let mut tooltip = SharedString::from_str(&button.label);
   // SAFETY: Discord's builder with the member list button's argument
   // shapes; it moves `tooltip` into the button and writes at most the
   // decoded button size, which fits `raw`.
   unsafe {
      build(
         raw.as_mut_ptr(),
         button.element.as_ptr(),
         button.element.len(),
         u32::from(button.icon),
         &raw mut tooltip,
         0,
         0,
         cx,
      );
   }
   // `tooltip` now belongs to the button, which has no Drop of ours to run.
   // SAFETY: `on_click` is inside the decoded button, which `raw` holds.
   let handler = unsafe {
      raw.as_mut_ptr()
         .add(on_click)
         .cast::<usize>()
         .read_unaligned()
   };
   // Leave ownership with the native button if it already has a handler.
   if handler == 0
      && let Some(rc) = gpui::alloc_rc_u64(button.id)
   {
      raw.put(on_click, [rc as usize, ptr::from_ref(&CLICK_VTBL) as usize]);
   }
   // SAFETY: `toolbar` is the live toolbar `append` just returned, and `raw`
   // holds a whole button, which `append` moves out of.
   unsafe {
      append(out.as_mut_ptr(), toolbar, raw.as_mut_ptr());
      ptr::copy_nonoverlapping(
         out.as_mut_ptr(),
         toolbar,
         TOOLBAR_SIZE.load(Ordering::Acquire),
      );
   }
}

/// The `Fn::call` slot of the click handler, shaped like Sunbird's own
/// buttons' (`gpui::button_callback`).
unsafe extern "C" fn on_click(
   data: *const u64,
   _event: *const c_void,
   _window: *mut c_void,
   _app: *mut c_void,
) {
   if data.is_null() {
      return;
   }
   // SAFETY: `data` is the `u64` in the `RcBox` `add` made.
   let id = unsafe { data.read() };
   let _ = worker().send(id);
}

fn worker() -> &'static mpsc::Sender<u64> {
   WORKER.get_or_init(|| {
      let (tx, rx) = mpsc::channel::<u64>();
      let _ = std::thread::Builder::new()
         .name("sunbird-header".to_owned())
         .spawn(move || {
            while let Ok(id) = rx.recv() {
               if let Some(engine) = phoenix_runtime::engine() {
                  crate::js::ui::press_header_button(&engine, id);
               }
            }
         });
      tx
   })
}
