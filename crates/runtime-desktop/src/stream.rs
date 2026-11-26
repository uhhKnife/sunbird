//! Phoenix's Go Live stream quality check, which while a plugin holds a
//! `phoenix.stream.unlockQuality()` handle stops locking high-resolution and
//! high-FPS stream options behind Nitro or server boost tiers, and the HD
//! preset stops opening a Nitro upsell.

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

/// `meetsApplicationStreamRequirements(&User, has_guild, guild_tier, preset,
/// resolution, fps) -> bool`.
type CheckFn = unsafe extern "C" fn(*const u8, u8, u8, u8, u32, u32) -> u8;

/// `canUsePremiumFeature(feature, tier, ctx) -> bool`.
type FeatureFn = unsafe extern "C" fn(u8, u8, *const u8) -> u8;

static UNLOCKED: AtomicBool = AtomicBool::new(false);
static CHECK: OnceLock<CheckFn> = OnceLock::new();
static FEATURE: OnceLock<FeatureFn> = OnceLock::new();
static STREAM_HIGH: OnceLock<u8> = OnceLock::new();

/// Hooks the checks from [`crate::prepare`], before Discord's threads run.
pub fn install(image: &Image<'static>) {
   install_quality(image);
   install_feature(image);
}

/// The HD preset, its "Unlock HD streaming" upsell and the picker's Nitro
/// banner ask the account's tier for `STREAM_HIGH_QUALITY` instead of the
/// quality table.
fn install_feature(image: &Image<'static>) {
   let found = match desktop::premium_feature(image) {
      Ok(found) => found,
      Err(err) => {
         log::warn!("stream feature: {err}, the HD preset stays locked");
         return;
      },
   };
   let Some(prologue) = desktop::Prologues::of(Abi::of(image)).premium_feature else {
      log::info!("stream feature: no prologue for this ABI, the HD preset stays locked");
      return;
   };
   let _ = STREAM_HIGH.set(found.stream_high);
   // SAFETY: runs before Discord's threads, and the detour matches the
   // check's ABI.
   let trampoline = match unsafe {
      image.hook_entry(
         found.func,
         prologue.pattern,
         prologue.len,
         can_use as *const () as usize,
      )
   } {
      Ok(trampoline) => trampoline,
      Err(err) => {
         log::warn!("stream feature: {err}");
         return;
      },
   };
   // SAFETY: the trampoline replays the displaced instructions and continues
   // in the check.
   let original = unsafe { std::mem::transmute::<usize, FeatureFn>(trampoline) };
   let _ = FEATURE.set(original);
   log::info!(
      "stream feature: hooked @ {:#x}, feature {:#x}",
      found.func,
      found.stream_high
   );
}

extern "C" fn can_use(feature: u8, tier: u8, ctx: *const u8) -> u8 {
   if UNLOCKED.load(Ordering::Acquire) && STREAM_HIGH.get() == Some(&feature) {
      return 1;
   }
   let &original = FEATURE.wait();
   // SAFETY: the trampoline runs the original leaf check.
   unsafe { original(feature, tier, ctx) }
}

fn install_quality(image: &Image<'static>) {
   let func = match desktop::stream_quality(image) {
      Ok(func) => func,
      Err(err) => {
         log::warn!("stream quality: {err}, Nitro stream tiers stay locked");
         return;
      },
   };
   let Some(prologue) = desktop::Prologues::of(Abi::of(image)).stream_quality else {
      log::info!("stream quality: no prologue for this ABI, tiers stay locked");
      return;
   };
   // SAFETY: runs before Discord's threads, and the detour matches the check's
   // ABI.
   let trampoline = match unsafe {
      image.hook_entry(
         func,
         prologue.pattern,
         prologue.len,
         can_stream as *const () as usize,
      )
   } {
      Ok(trampoline) => trampoline,
      Err(err) => {
         log::warn!("stream quality: {err}");
         return;
      },
   };
   // SAFETY: the trampoline replays the displaced instructions and continues
   // in the check.
   let original = unsafe { std::mem::transmute::<usize, CheckFn>(trampoline) };
   let _ = CHECK.set(original);
   log::info!("stream quality: hooked @ {func:#x}");
}

/// While `on`, Go Live resolutions and framerates locked behind Nitro or boost
/// tiers count as available.
pub fn unlock(on: bool) {
   UNLOCKED.store(on, Ordering::Release);
}

extern "C" fn can_stream(
   user: *const u8,
   has_guild: u8,
   guild_tier: u8,
   preset: u8,
   resolution: u32,
   fps: u32,
) -> u8 {
   if UNLOCKED.load(Ordering::Acquire) {
      // The check decides from the account's own Nitro tier, and the picker
      // hands it the real user: a copy with every byte set to 1 reads as Nitro
      // Basic, which still refuses Source and 1080p at 60. Answering true
      // directly keeps the goods of the table without guessing struct offsets.
      return 1;
   }
   let &original = CHECK.wait();
   // SAFETY: the trampoline runs the original leaf check.
   unsafe { original(user, has_guild, guild_tier, preset, resolution, fps) }
}
