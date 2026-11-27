//! The composer's Nitro gift button, which `phoenix.ui.hide("composer.gift")`
//! leaves out.

use std::sync::{
   Mutex,
   OnceLock,
   PoisonError,
};

use phoenix_hook::image::Image;
use phoenix_sigs::desktop;

/// `jne rel32`, and `nop; jmp rel32` to the same place on x86-64.
const SHOWN: [u8; 2] = [0x0F, 0x85];
const HIDDEN: [u8; 2] = [0x90, 0xE9];

struct Patch {
   site:   usize,
   shown:  [u8; 4],
   hidden: [u8; 4],
   len:    usize,
}

static GIFT: OnceLock<Patch> = OnceLock::new();
/// Plugins holding the gift button hidden.
static HIDERS: Mutex<usize> = Mutex::new(0);

/// Finds the gift button's branch from [`crate::prepare`], while the locator
/// indexes are built.
pub fn install(image: &Image<'static>) {
   if crate::X86_CODE {
      match desktop::composer_gift(image) {
         Ok(site) if image.read(site, 2) == Some(&SHOWN[..]) => {
            let _ = GIFT.set(Patch {
               site,
               shown: [SHOWN[0], SHOWN[1], 0, 0],
               hidden: [HIDDEN[0], HIDDEN[1], 0, 0],
               len: 2,
            });
         },
         Ok(site) => log::warn!("composer gift: {site:#x} is no jne"),
         Err(err) => log::warn!("composer gift: {err}, the gift button stays"),
      }
   } else {
      match phoenix_sigs::macos::composer_gift(image) {
         Ok(gift) => {
            let _ = GIFT.set(Patch {
               site:   gift.site,
               shown:  gift.shown.to_le_bytes(),
               hidden: gift.hidden.to_le_bytes(),
               len:    4,
            });
         },
         Err(err) => log::warn!("composer gift: {err}, the gift button stays"),
      }
   }
}

/// Hides the gift button until the matching `hide_gift(false)`. False when
/// this build's button was not found.
pub fn hide_gift(hide: bool) -> bool {
   let (Some(patch), Some(state)) = (GIFT.get(), phoenix_runtime::state()) else {
      return false;
   };
   let mut hiders = HIDERS.lock().unwrap_or_else(PoisonError::into_inner);
   let next = if hide {
      *hiders + 1
   } else {
      hiders.saturating_sub(1)
   };
   if (*hiders > 0) != (next > 0) {
      let bytes = if hide {
         &patch.hidden[..patch.len]
      } else {
         &patch.shown[..patch.len]
      };
      // SAFETY: all patch bytes lie in one aligned word, which the locator
      // checked, so a thread at the branch reads the old or the new opcode
      // whole.
      if let Err(err) = unsafe { state.image.write_code(patch.site, bytes) } {
         log::error!("composer gift: {err}");
         return false;
      }
   }
   *hiders = next;
   true
}
