//! Collapsing the channel sidebar, for `phoenix.ui.collapseChannels`.
//!
//! The workspace sizes the sidebar from `SidebarResize`'s width, which the
//! resize handle clamps to 264..432 px, so the width itself can't reach the
//! server rail. While collapsed, the two calls that read the width for layout
//! answer the rail plus its 1 px border instead, which leaves the channel
//! column 0 px wide and tells other views the sidebar ends at the rail. The
//! stored width stays, so restoring brings back the user's own width, and the
//! resize handle is left out as when an overlay covers the workspace.

use std::{
   ffi::c_void,
   sync::{
      Mutex,
      OnceLock,
      PoisonError,
      atomic::{
         AtomicBool,
         Ordering,
      },
   },
};

use phoenix_hook::image::Image;
use phoenix_sigs::desktop;

/// `f32 width(&RootModel, &App)`.
type WidthFn = unsafe extern "C" fn(*const c_void, *const c_void) -> f32;
/// `f32 rail()`.
type RailFn = unsafe extern "C" fn() -> f32;
/// `bool covered(&RootModel)`.
type CoveredFn = unsafe extern "C" fn(*const c_void) -> bool;

/// The server rail's right border, which the column's width leaves out.
const RAIL_BORDER: f32 = 1.0;

static COLLAPSED: AtomicBool = AtomicBool::new(false);
static WIDTH: OnceLock<WidthFn> = OnceLock::new();
static RAIL: OnceLock<RailFn> = OnceLock::new();
static COVERED: OnceLock<CoveredFn> = OnceLock::new();
/// Whether every call site was hooked, so collapsing can take effect.
static READY: AtomicBool = AtomicBool::new(false);
/// Plugins holding the sidebar collapsed.
static HOLDERS: Mutex<usize> = Mutex::new(0);

/// Hooks the width and handle call sites from [`crate::prepare`], before
/// Discord's threads run.
pub fn install(image: &Image<'static>) {
   if !cfg!(all(target_os = "windows", target_arch = "x86_64")) {
      return;
   }
   let found = match desktop::channel_sidebar(image) {
      Ok(found) => found,
      Err(err) => {
         log::warn!("channel sidebar: {err}, it stays");
         return;
      },
   };
   // SAFETY: `rail` is a leaf taking no arguments and returning an `f32`,
   // which the locator checked by its caller subtracting it from the width.
   let _ = RAIL.set(unsafe { std::mem::transmute::<usize, RailFn>(found.rail) });
   let hooked = [found.column_site, found.publish_site]
      .into_iter()
      .all(|site| {
         hook(image, site, width_detour as *const () as usize, |target| {
            // SAFETY: both sites call the locator's `width(root, cx)`, the same
            // getter, so a second `set` would store the same function.
            let _ = WIDTH.set(unsafe { std::mem::transmute::<usize, WidthFn>(target) });
         })
      })
      && hook(
         image,
         found.handle_site,
         covered_detour as *const () as usize,
         |target| {
            // SAFETY: the call's own target, `covered(&RootModel) -> bool`.
            let _ = COVERED.set(unsafe { std::mem::transmute::<usize, CoveredFn>(target) });
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
         log::info!("channel sidebar: hooked @ {site:#x}");
         true
      },
      Err(err) => {
         log::warn!("channel sidebar: hook @ {site:#x} failed: {err}");
         false
      },
   }
}

/// Holds the sidebar collapsed until the matching `collapse(false)`. False when
/// this build's sidebar was not found.
pub fn collapse(hold: bool) -> bool {
   if !ready() {
      return false;
   }
   let mut holders = HOLDERS.lock().unwrap_or_else(PoisonError::into_inner);
   *holders = if hold {
      *holders + 1
   } else {
      holders.saturating_sub(1)
   };
   let collapsed = *holders > 0;
   let changed = COLLAPSED.swap(collapsed, Ordering::AcqRel) != collapsed;
   drop(holders);
   if changed {
      crate::accessories::invalidate_discord_windows();
   }
   true
}

pub fn ready() -> bool {
   READY.load(Ordering::Acquire)
}

unsafe extern "C" fn width_detour(root: *const c_void, cx: *const c_void) -> f32 {
   if COLLAPSED.load(Ordering::Acquire)
      && let Some(rail) = RAIL.get()
   {
      // SAFETY: the rail width reads only Discord's density setting.
      return unsafe { rail() } + RAIL_BORDER;
   }
   // The width call sites are only hooked once `WIDTH` holds their target.
   let width = *WIDTH.wait();
   // SAFETY: forwards the getter's own arguments.
   unsafe { width(root, cx) }
}

unsafe extern "C" fn covered_detour(root: *const c_void) -> bool {
   if COLLAPSED.load(Ordering::Acquire) {
      return true;
   }
   let covered = *COVERED.wait();
   // SAFETY: forwards the predicate's own argument.
   unsafe { covered(root) }
}
