//! Phoenix's Go Live stream quality check and its premium feature check.
//! While a plugin holds a `phoenix.stream.unlockQuality()` handle, high
//! resolutions and framerates stop being locked behind Nitro or server boost
//! tiers and the HD preset stops opening a Nitro upsell. While one holds a
//! `phoenix.appearance.unlockNitro()` handle, Nitro color themes and app icons
//! can be picked.

use std::sync::{
   OnceLock,
   atomic::{
      AtomicBool,
      AtomicU32,
      AtomicUsize,
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

static UNLOCKED: AtomicBool = AtomicBool::new(false);
static CHECK: OnceLock<CheckFn> = OnceLock::new();
static STREAM_HIGH: OnceLock<u8> = OnceLock::new();
static APP_ICONS: OnceLock<u8> = OnceLock::new();

/// `perks(out, store) -> out`, the premium perks accessor.
type PerksFn = unsafe extern "C" fn(*mut u8, *const u8) -> *mut u8;

static PERKS: OnceLock<PerksFn> = OnceLock::new();
static THEME_FIELD: OnceLock<u8> = OnceLock::new();
static THEMES_UNLOCKED: AtomicBool = AtomicBool::new(false);

/// One bit per feature id `phoenix_can_use` answers true for: the plugins'
/// unlocks and the console's, combined once on each change.
static FORCED: AtomicU32 = AtomicU32::new(0);
/// The trampoline into `canUsePremiumFeature`, past its displaced prologue.
static FEATURE_ORIGINAL: AtomicUsize = AtomicUsize::new(0);
static PLUGIN_FEATURES: AtomicU32 = AtomicU32::new(0);
static CONSOLE_FEATURES: AtomicU32 = AtomicU32::new(0);

const fn bit(feature: u8) -> u32 {
   if feature < 32 { 1 << feature } else { 0 }
}

fn refresh_forced() {
   FORCED.store(
      PLUGIN_FEATURES.load(Ordering::Acquire) | CONSOLE_FEATURES.load(Ordering::Acquire),
      Ordering::Release,
   );
}

fn force_plugin(bits: u32, on: bool) {
   if on {
      PLUGIN_FEATURES.fetch_or(bits, Ordering::AcqRel);
   } else {
      PLUGIN_FEATURES.fetch_and(!bits, Ordering::AcqRel);
   }
   refresh_forced();
}

/// Hooks the checks from [`crate::prepare`], before Discord's threads run.
pub fn install(image: &Image<'static>) {
   install_quality(image);
   install_feature(image);
   install_theme_perk(image);
}

/// Appearance, Theme reads one byte of the premium perks, built from the
/// account's tier, to choose between its Nitro page and the locked one.
fn install_theme_perk(image: &Image<'static>) {
   let perk = match desktop::theme_perk(image) {
      Ok(perk) => perk,
      Err(err) => {
         log::warn!("theme perk: {err}, Nitro color themes stay locked");
         return;
      },
   };
   let Some(prologue) = desktop::Prologues::of(Abi::of(image)).perks else {
      return;
   };
   let _ = THEME_FIELD.set(perk.field);
   // SAFETY: runs before Discord's threads, and the detour matches the
   // accessor's ABI. The accessor calls on into the store, so its callers
   // keep nothing in volatile registers across it.
   let trampoline = match unsafe {
      image.hook_entry(
         perk.accessor,
         prologue.pattern,
         prologue.len,
         perks as *const () as usize,
      )
   } {
      Ok(trampoline) => trampoline,
      Err(err) => {
         log::warn!("theme perk: {err}");
         return;
      },
   };
   // SAFETY: the trampoline replays the displaced instructions and continues
   // in the accessor.
   let original = unsafe { std::mem::transmute::<usize, PerksFn>(trampoline) };
   let _ = PERKS.set(original);
   log::info!(
      "theme perk: hooked @ {:#x}, field +{:#x}",
      perk.accessor,
      perk.field
   );
}

extern "C" fn perks(out: *mut u8, store: *const u8) -> *mut u8 {
   let &original = PERKS.wait();
   // SAFETY: the trampoline runs the original accessor.
   let perks = unsafe { original(out, store) };
   if THEMES_UNLOCKED.load(Ordering::Acquire)
      && !perks.is_null()
      && let Some(&field) = THEME_FIELD.get()
   {
      // SAFETY: the accessor filled its 0x58-byte perks, and the field was
      // read from the theme section's load inside them.
      unsafe { perks.add(usize::from(field)).write(1) };
   }
   perks
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
   match found.app_icons {
      Some(app_icons) => {
         let _ = APP_ICONS.set(app_icons);
      },
      None => log::warn!("premium feature: tier lists changed, Nitro app icons stay locked"),
   }
   if !hook_feature(image, found.func, prologue) {
      return;
   }
   log::info!(
      "stream feature: hooked @ {:#x}, feature {:#x}",
      found.func,
      found.stream_high
   );
}

/// Sets the features the console forces on with `phoenix.native.premium(mask)`,
/// one bit per feature id, to find which feature a Nitro screen asks for.
/// Returns every feature now forced, the plugins' included.
pub fn force_console(mask: u32) -> u32 {
   CONSOLE_FEATURES.store(mask, Ordering::Release);
   refresh_forced();
   FORCED.load(Ordering::Acquire)
}

// The detour for `canUsePremiumFeature(cl = feature, dl = tier, r8 = ctx,
// r9 = overrides)`, a leaf Discord asks thousands of times a second. Its
// callers keep values in registers the leaf leaves alone: a Rust detour that
// answered the same crashed a fat-LTO build at startup and changed screens it
// gave no answer for. So it touches only rax and r10, which the leaf
// overwrites itself, never the stack, and jumps on into the leaf with every
// argument as it came.
#[cfg(all(windows, target_arch = "x86_64"))]
std::arch::global_asm!(
   ".globl phoenix_can_use",
   ".p2align 4",
   "phoenix_can_use:",
   "movzx eax, cl",
   "cmp eax, 32",
   "jae 2f",
   "mov r10d, dword ptr [rip + {forced}]",
   "bt r10d, eax",
   "jnc 2f",
   "mov eax, 1",
   "ret",
   "2:",
   "jmp qword ptr [rip + {original}]",
   forced = sym FORCED,
   original = sym FEATURE_ORIGINAL,
);

#[cfg(all(windows, target_arch = "x86_64"))]
unsafe extern "C" {
   fn phoenix_can_use();
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn hook_feature(image: &Image<'static>, func: usize, prologue: desktop::Prologue) -> bool {
   // SAFETY: runs before Discord's threads, and the detour keeps the leaf's
   // registers and arguments.
   let trampoline = match unsafe {
      image.hook_entry(
         func,
         prologue.pattern,
         prologue.len,
         phoenix_can_use as *const () as usize,
      )
   } {
      Ok(trampoline) => trampoline,
      Err(err) => {
         log::warn!("stream feature: {err}");
         return false;
      },
   };
   FEATURE_ORIGINAL.store(trampoline, Ordering::Release);
   true
}

// Only Win64 has a prologue, so this is never reached elsewhere.
#[cfg(not(all(windows, target_arch = "x86_64")))]
fn hook_feature(_image: &Image<'static>, _func: usize, _prologue: desktop::Prologue) -> bool {
   false
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
   if let Some(&stream_high) = STREAM_HIGH.get() {
      force_plugin(bit(stream_high), on);
   }
}

/// While `on`, Nitro color themes and app icons count as available.
pub fn unlock_appearance(on: bool) {
   THEMES_UNLOCKED.store(on, Ordering::Release);
   if let Some(&app_icons) = APP_ICONS.get() {
      force_plugin(bit(app_icons), on);
   }
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
