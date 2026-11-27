//! Injects a native GPUI **Sunbird** tab directly into Desktop Phoenix's User
//! Settings sidebar and renders native Mana GPUI settings controls when
//! selected.
//!
//! All patches are build-independent anchor lookups run from [`crate::prepare`]
//! inside `DllMain` before Discord initializes:
//! 1. Relabel settings page `24` (`Other -> Phoenix`, right above `Log Out`) to
//!    `Sunbird` by replacing the unique 22-byte `.rdata` string
//!    `PhoenixDESKTOP_PHOENIX` in-place with `SunbirdDESKTOP_SUNBIRD`.
//! 2. Unconditionally show page `24` in `is_page_visible` by tightening the
//!    `cmp r8d, 0xf` range guard (`pages 9..=24`) to `0x0e` (`pages 9..=23`),
//!    so page `24` falls through to `return true`.
//! 3. Resolve Discord's native GPUI/Mana widget builders ([`crate::gpui`]) and
//!    inline-hook `host::section` (located via the unique `account-loading`
//!    string xref and `.pdata` function bounds) so when active page `== 24`, it
//!    builds and returns a native GPUI `AnyElement` directly into Discord's
//!    User Settings scroll viewport.

use std::{
   ffi::c_void,
   sync::{
      OnceLock,
      atomic::{
         AtomicUsize,
         Ordering,
      },
   },
};

use phoenix_hook::image::Image;
use phoenix_sigs::{
   index::Index,
   locate,
};

use crate::gpui::{
   self,
   RawAnyElement,
};

/// The last flag-gated settings page, which Sunbird takes over (`24`, from
/// `sub #9; cmp #0xf`).
const SUNBIRD_PAGE: u8 = 24;

type SectionFn = unsafe extern "C" fn(
   sret: *mut RawAnyElement,
   host_state: *mut c_void,
   host_data: *mut c_void,
   host_vtable: *const c_void,
   window: *mut c_void,
   cx: *mut c_void,
) -> *mut RawAnyElement;

static ORIG_SECTION: OnceLock<SectionFn> = OnceLock::new();
static PAGE_OFFSET: AtomicUsize = AtomicUsize::new(0);
/// The page the last section render showed, so the arm64 page opens the
/// settings window once per visit rather than once per frame.
static LAST_PAGE: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Installs the Desktop User Settings sidebar label, visibility patch, native
/// GPUI builder bindings, and `host::section` render hook.
pub fn install(image: &Image<'static>, ix: &Index<'_>) {
   if !crate::X86_CODE {
      #[cfg(target_os = "macos")]
      install_arm64(image, ix);
      return;
   }
   patch_sidebar_label(image, ix);
   patch_page_visibility(image, ix);
   if gpui::locate(image, ix) {
      hook_section_render(image, ix);
   }
}

/// macOS Phoenix, arm64: the same sidebar entry, unhidden, whose page is
/// drawn with Discord's own builders ([`gpui::locate`]), or opens Sunbird's
/// settings window when they don't decode. Each part is located before
/// anything is written, so a build that moved one changes nothing.
#[cfg(target_os = "macos")]
fn install_arm64(image: &Image<'static>, ix: &Index<'_>) {
   use phoenix_sigs::macos;

   const NEW_NAME: &[u8] = b"Sunbird";
   const NEW_SUFFIX: &[u8] = b"SUNBIRD";

   // Locate GPUI symbols and Discord's allocator up front so early exits below
   // cannot silently disable icons, modals, or other native GPUI features.
   let native = gpui::locate(image, ix);

   let (label, limits, section) = match (
      locate::settings::settings_label(ix),
      locate::settings::settings_visibility(ix),
      locate::settings::settings_section(ix),
   ) {
      (Ok(label), Ok(limits), Ok(section)) => (label, limits, section),
      (label, limits, section) => {
         let err = [label.err(), limits.err(), section.err()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join("; ");
         log::warn!("desktop settings: {err}, leaving the sidebar");
         return;
      },
   };
   let Some(guards) = limits
      .iter()
      .map(|guard| {
         image
            .read_u32(guard.cmp)
            .map(|cmp| (guard.cmp, macos::lowered_guard(cmp)))
      })
      .collect::<Option<Vec<_>>>()
   else {
      log::warn!("desktop settings: visibility guard unmapped");
      return;
   };
   PAGE_OFFSET.store(section.page_offset, Ordering::Release);
   // SAFETY: runs from `prepare` before Discord's threads; `section_detour`
   // matches `host::section`'s x86-style 6-argument sret ABI.
   let Some(orig) = (unsafe {
      crate::hook_sret::<SectionFn>(
         image,
         |pro| pro.frame,
         section.func,
         section_detour as *const () as usize,
         "desktop settings: section hook failed",
      )
   }) else {
      return;
   };
   let _ = ORIG_SECTION.set(orig);
   // SAFETY: exact-length string and one-instruction patches from `prepare`,
   // before Discord's threads run.
   let written = unsafe {
      guards
         .iter()
         .try_for_each(|&(limit, lowered)| image.write_code(limit, &lowered.to_le_bytes()))
         .and_then(|()| image.write_code(label.name, NEW_NAME))
         .and_then(|()| image.write_code(label.suffix, NEW_SUFFIX))
   };
   match written {
      Ok(()) => {
         log::info!(
            "desktop settings: page {SUNBIRD_PAGE} is Sunbird, shown by {} visibility checks, {}",
            guards.len(),
            if native {
               "drawn natively"
            } else {
               "and opens the settings window"
            }
         );
      },
      Err(err) => log::warn!("desktop settings: {err}"),
   }
}

fn patch_sidebar_label(image: &Image<'static>, ix: &Index<'_>) {
   const NEW_NAME: &[u8] = b"Sunbird";
   const NEW_SUFFIX: &[u8] = b"SUNBIRD";
   const _: () = assert!(NEW_NAME.len() == b"Phoenix".len());
   const _: () = assert!(NEW_SUFFIX.len() == b"PHOENIX".len());

   let label = match locate::settings::settings_label(ix) {
      Ok(label) => label,
      Err(err) => {
         log::warn!("desktop settings: {err}, leaving sidebar label");
         return;
      },
   };
   // SAFETY: exact-length `.rodata`/`.rdata` string patches executed from
   // `prepare` before Discord threads run.
   if let Err(err) = unsafe { image.write_code(label.name, NEW_NAME) } {
      log::warn!("desktop settings: relabel name failed: {err}");
      return;
   }
   // SAFETY: as above. The id ends in the suffix, `DESKTOP_PHOENIX` or
   // `PHOENIX`, so this gives `DESKTOP_SUNBIRD` or `SUNBIRD`.
   match unsafe { image.write_code(label.suffix, NEW_SUFFIX) } {
      Ok(()) => log::info!("desktop settings: relabeled page 24 to Sunbird"),
      Err(err) => log::warn!("desktop settings: relabel id failed: {err}"),
   }
}

fn patch_page_visibility(image: &Image<'static>, ix: &Index<'_>) {
   let guards = match locate::settings::settings_visibility(ix) {
      Ok(guards) => guards,
      Err(err) => {
         log::warn!("desktop settings: {err}, leaving it");
         return;
      },
   };
   // Tightening `cmp r8d, 0xf` -> `0x0e` excludes page 24 (`24 - 9 = 15`) from
   // the gated switch so `is_page_visible(24)` returns `true` unconditionally.
   for guard in guards {
      // SAFETY: single-byte immediate patch in `.text` executed from `DllMain`.
      match unsafe { image.write_code(guard.imm8(), &[0x0E]) } {
         Ok(()) => log::info!("desktop settings: page 24 visible @ {:#x}", guard.cmp),
         Err(err) => log::warn!("desktop settings: visibility patch failed: {err}"),
      }
   }
}

fn hook_section_render(image: &Image<'static>, ix: &Index<'_>) {
   let (fn_start, offset) = match locate::settings::settings_section(ix) {
      Ok(section) => (section.func, section.page_offset),
      Err(err) => {
         log::warn!("desktop settings: {err}, skipping section hook");
         return;
      },
   };
   PAGE_OFFSET.store(offset, Ordering::Release);

   // SAFETY: runs from `prepare` before Discord threads execute;
   // `section_detour` matches `host::section`'s exact 6-argument sret ABI.
   let Some(orig) = (unsafe {
      crate::hook_sret::<SectionFn>(
         image,
         |pro| pro.frame,
         fn_start,
         section_detour as *const () as usize,
         "desktop settings: section hook failed",
      )
   }) else {
      return;
   };
   let _ = ORIG_SECTION.set(orig);
   log::info!("desktop settings: hooked section render @ {fn_start:#x} (page offset {offset:#x})");
}

unsafe extern "C" fn section_detour(
   sret: *mut RawAnyElement,
   host_state: *mut c_void,
   host_data: *mut c_void,
   host_vtable: *const c_void,
   window: *mut c_void,
   cx: *mut c_void,
) -> *mut RawAnyElement {
   if !host_state.is_null() && !sret.is_null() {
      let offset = PAGE_OFFSET.load(Ordering::Acquire);
      // SAFETY: `host_state` is Discord's live `&mut HostState` for this render
      // call.
      let page = unsafe { *host_state.cast::<u8>().add(offset) };
      let last = LAST_PAGE.swap(usize::from(page), Ordering::AcqRel);
      if !crate::X86_CODE
         && page == SUNBIRD_PAGE
         && last != usize::from(page)
         && gpui::layout().is_none()
      {
         // Opening spawns a browser, which must not run on GPUI's thread.
         let _ = std::thread::Builder::new()
            .name("sunbird-settings".to_owned())
            .spawn(phoenix_ui_desktop::open_devtools);
      }
      if page == SUNBIRD_PAGE {
         let rendered =
            std::panic::catch_unwind(|| gpui::render_sunbird_page(sret)).unwrap_or(false);
         if rendered {
            return sret;
         }
      }
   }
   let Some(orig) = ORIG_SECTION.get().copied() else {
      return sret;
   };
   // SAFETY: forwards all arguments verbatim to the original `host::section`.
   unsafe { orig(sret, host_state, host_data, host_vtable, window, cx) }
}
