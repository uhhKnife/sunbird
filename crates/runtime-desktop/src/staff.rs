//! Phoenix's Staff Settings page reads a local flag computed as
//! `(user.flags | flag_override) & 1`, where `flag_override` is Phoenix's own
//! client-side field. Setting its low bit shows the page.
//!
//! The read is inlined off the gateway handler's first argument, so the gateway
//! detour writes `flag_override` in that state while the reducer holds it.

use std::{
   ffi::c_void,
   ptr,
   sync::{
      OnceLock,
      atomic::{
         AtomicBool,
         Ordering,
      },
   },
};

use phoenix_hook::image::Image;
use phoenix_sigs::{
   StaffField as Field,
   index::{
      Index,
      Isa,
   },
};

const STAFF: u64 = 1;

static LOCATED: OnceLock<Option<Field>> = OnceLock::new();
static LOGGED: AtomicBool = AtomicBool::new(false);

/// Scans Discord synchronously from `prepare` so `flag_override` is ready
/// before the first gateway event fires.
pub fn prepare(ix: &Index<'_>) {
   LOCATED.get_or_init(|| locate(ix));
}

/// Locates on its own index when [`prepare`] did not run.
pub fn start(image: &'static Image<'static>) {
   LOCATED.get_or_init(|| locate(&Index::new(image, Isa::HOST)));
}

fn locate(ix: &Index<'_>) -> Option<Field> {
   let field = phoenix_sigs::locate::staff::staff(ix)
      .inspect_err(|err| log::warn!("staff: {err}, leaving flag_override as is"))
      .ok()?
      .field;
   log::info!(
      "staff: located flag_override at tag={:#x} value={:#x}",
      field.tag,
      field.value
   );
   Some(field)
}

/// # Safety
///
/// `state` is the `&StoreState` a gateway handler was called with, and the
/// caller runs inside that handler.
pub unsafe fn apply(state: *mut c_void) {
   let Some(Some(field)) = LOCATED.get() else {
      return;
   };
   if state.is_null() {
      return;
   }
   // SAFETY: the flag read loads `tag` as `u32` (`1` == `Some`) and `value`
   // as `u64` from `&StoreState`, which every gateway handler receives first.
   unsafe {
      let tag = state.byte_add(field.tag).cast::<u32>();
      let value = state.byte_add(field.value).cast::<u64>();
      // An `Option` tag is 0 or 1. Anything else means the offset doesn't
      // fit this state, so nothing is written.
      if ptr::read(tag) > 1 {
         if !LOGGED.swap(true, Ordering::AcqRel) {
            log::warn!(
               "staff: flag_override's tag reads {}, leaving it",
               ptr::read(tag)
            );
         }
         return;
      }
      let had = ptr::read(tag) == 1;
      let current = if had { ptr::read(value) } else { 0 };
      let wanted = if phoenix_runtime::staff_enabled() {
         current | STAFF
      } else {
         current & !STAFF
      };
      if wanted == current {
         return;
      }
      ptr::write(value, wanted);
      ptr::write(tag, u32::from(wanted != 0));
   }
   if phoenix_runtime::staff_enabled() && !LOGGED.swap(true, Ordering::AcqRel) {
      log::info!("staff: unlocked (flag_override bit 0 set)");
   }
}
