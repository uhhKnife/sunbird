//! Phoenix's sticker check, which while a plugin holds
//! `phoenix.messages.unlockStickers` answers sendable for stickers that need
//! Nitro. The picker then sends them, and the plugin rewrites the send.

use std::sync::{
   OnceLock,
   atomic::{
      AtomicBool,
      Ordering,
   },
};

use phoenix_hook::{
   image::Image,
   x86::Abi,
};
use phoenix_sigs::desktop;

/// `getStickerSendability(&StickerContext, &Sticker) -> u8`.
type CheckFn = unsafe extern "C" fn(*const u8, *const u8) -> u8;

const SENDABLE: u8 = 0;
const SENDABLE_WITH_PREMIUM: u8 = 1;

static UNLOCKED: AtomicBool = AtomicBool::new(false);
static CHECK: OnceLock<CheckFn> = OnceLock::new();

/// Hooks the check from [`crate::prepare`], before Discord's threads run.
pub fn install(image: &Image<'static>) {
   let (func, prologue) = match (
      desktop::sticker_check(image),
      desktop::Prologues::of(Abi::of(image)).sticker_check,
   ) {
      (Ok(func), Some(prologue)) => (func, prologue),
      (Err(err), _) => {
         log::warn!("sticker check: {err}, Nitro stickers stay locked");
         return;
      },
      (_, None) => return,
   };
   // SAFETY: runs before Discord's threads, and the detour has the check's
   // ABI.
   let trampoline = match unsafe {
      image.hook_entry(
         func,
         prologue.pattern,
         prologue.len,
         sendability as *const () as usize,
      )
   } {
      Ok(trampoline) => trampoline,
      Err(err) => {
         log::warn!("sticker check: {err}");
         return;
      },
   };
   // SAFETY: the trampoline replays the displaced prologue and continues in
   // the check.
   let _ = CHECK.set(unsafe { std::mem::transmute::<usize, CheckFn>(trampoline) });
   log::info!("sticker check: hooked @ {func:#x}");
}

/// While `on`, stickers Phoenix keeps for Nitro count as sendable. Stickers
/// it would not send at all stay that way.
pub fn unlock(on: bool) {
   UNLOCKED.store(on, Ordering::Release);
}

extern "C" fn sendability(context: *const u8, sticker: *const u8) -> u8 {
   // The jump is written just before `CHECK` is set, all before Discord runs.
   let original = *CHECK.wait();
   // SAFETY: the trampoline runs the original check with Phoenix's arguments.
   let answer = unsafe { original(context, sticker) };
   if answer == SENDABLE_WITH_PREMIUM && UNLOCKED.load(Ordering::Acquire) {
      SENDABLE
   } else {
      answer
   }
}
