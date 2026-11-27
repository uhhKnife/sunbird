//! Plugin decorations keyed by user id for Desktop Phoenix: the member list
//! and DM list (`phoenix.ui.addMemberDecoration`) and message headers
//! (`phoenix.ui.addMessageHeaderDecoration`, drawn by [`crate::headers`]).
//!
//! In the member list's row renderer, the function formatting `member-{}-{}`
//! found by [`desktop::member_row`], the calls adding the member's name to its
//! row are pointed at a detour that adds plugin decorations right after it.

use std::{
   collections::HashMap,
   ffi::c_void,
   sync::{
      LazyLock,
      OnceLock,
      RwLock,
      atomic::{
         AtomicUsize,
         Ordering,
      },
      mpsc,
   },
};

use phoenix_hook::image::Image;
use phoenix_sigs::desktop;

use crate::{
   accessories::{
      RenderedAccessory,
      invalidate_discord_windows,
   },
   gpui,
};

/// `Div::child` by value, as the name row adds the name: `(sret, div, &name)`.
type NameChildFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> *mut c_void;

enum CacheEntry {
   Pending,
   Ready(Vec<RenderedAccessory>),
}

const MAX_CACHE_ENTRIES: usize = 8192;
/// Snowflakes from 2015 on are far above this, so anything below is not an id.
pub const MIN_SNOWFLAKE: u64 = 1 << 40;

/// Where decorations keyed by user id go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
   /// After names in the member list.
   Members,
   /// After authors' names in message headers.
   Headers,
}

impl Place {
   pub const fn decorations(self) -> &'static Decorations {
      match self {
         Self::Members => &MEMBERS,
         Self::Headers => &HEADERS,
      }
   }
}

/// What a [`Place`]'s decorations drew per user, filled on a worker thread so
/// Discord's render never waits on plugins.
pub struct Decorations {
   place:  Place,
   active: AtomicUsize,
   cache:  LazyLock<RwLock<HashMap<u64, CacheEntry>>>,
   worker: OnceLock<mpsc::Sender<u64>>,
}

pub static MEMBERS: Decorations = Decorations::new(Place::Members);
pub static HEADERS: Decorations = Decorations::new(Place::Headers);

impl Decorations {
   const fn new(place: Place) -> Self {
      Self {
         place,
         active: AtomicUsize::new(0),
         cache: LazyLock::new(|| RwLock::new(HashMap::new())),
         worker: OnceLock::new(),
      }
   }

   pub fn active(&self) -> bool {
      self.active.load(Ordering::Relaxed) > 0
   }

   pub fn set_active_count(&'static self, count: usize) {
      self.active.store(count, Ordering::Release);
      if count > 0 {
         self.ensure_worker();
      }
   }

   pub fn clear_cache(&self) {
      if let Ok(mut map) = self.cache.write() {
         map.clear();
      }
   }

   /// Stores what the decorations drew for `user_id` and repaints when it
   /// changed.
   pub fn set_rendered(&self, user_id: u64, mut items: Vec<RenderedAccessory>) {
      items.sort_by_key(|a| a.priority);
      let changed = self.cache.write().is_ok_and(|mut map| {
         if map.len() > MAX_CACHE_ENTRIES {
            map.clear();
         }
         let same = matches!(map.get(&user_id), Some(CacheEntry::Ready(old)) if *old == items);
         map.insert(user_id, CacheEntry::Ready(items));
         !same
      });
      if changed {
         invalidate_discord_windows();
      }
   }

   fn ensure_worker(&'static self) -> &'static mpsc::Sender<u64> {
      self.worker.get_or_init(|| {
         let (tx, rx) = mpsc::channel::<u64>();
         let name = match self.place {
            Place::Members => "sunbird-members",
            Place::Headers => "sunbird-headers",
         };
         let _ = std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
               while let Ok(id) = rx.recv() {
                  let mut batch = vec![id];
                  while let Ok(more) = rx.try_recv() {
                     if !batch.contains(&more) {
                        batch.push(more);
                     }
                  }
                  for uid in batch {
                     if self.active.load(Ordering::Acquire) == 0 {
                        break;
                     }
                     let items = phoenix_runtime::engine().map_or_default(|engine| {
                        crate::js::ui::render_decorations(&engine, self.place, uid)
                     });
                     self.set_rendered(uid, items);
                  }
               }
            });
         tx
      })
   }

   /// What the decorations drew for `user_id`, queueing them when unknown.
   pub fn lookup(&'static self, user_id: u64) -> Option<Vec<RenderedAccessory>> {
      if let Ok(map) = self.cache.read()
         && let Some(entry) = map.get(&user_id)
      {
         return match entry {
            CacheEntry::Ready(items) if !items.is_empty() => Some(items.clone()),
            _ => None,
         };
      }
      let queue = self.cache.write().is_ok_and(|mut map| {
         if map.contains_key(&user_id) {
            return false;
         }
         if map.len() > MAX_CACHE_ENTRIES {
            map.clear();
         }
         map.insert(user_id, CacheEntry::Pending);
         true
      });
      if queue {
         let _ = self.ensure_worker().send(user_id);
      }
      None
   }
}

static ORIG_NAME_CHILD: OnceLock<NameChildFn> = OnceLock::new();
/// Where the name detour finds the closure's environment: `[frame+slot]`, or
/// the frame itself with [`ENV_IS_FRAME`].
static CLOSURE_SLOT: AtomicUsize = AtomicUsize::new(ENV_IS_FRAME);
const ENV_IS_FRAME: usize = usize::MAX;
static ENV_USER_ID: AtomicUsize = AtomicUsize::new(0);

/// Locates the member row and hooks the calls adding its name, from
/// `DllMain`.
pub fn install(image: &Image<'static>) {
   if !gpui::supports_accessories() {
      log::warn!("desktop members: GPUI text/push primitives unavailable, skipping");
      return;
   }
   // Without it, decorations show their text instead of icons.
   gpui::locate_svg(image);
   if !crate::X86_CODE {
      #[cfg(target_os = "macos")]
      arm64::install(image);
      return;
   }
   match desktop::member_row(image) {
      Ok(row) => install_name(image, &row.name),
      Err(err) => log::warn!("desktop members: {err}, skipping"),
   }
   match desktop::dm_row(image) {
      Ok(row) => install_dm(image, &row),
      Err(err) => log::warn!("desktop members: {err}, skipping the DM list"),
   }
}

/// The callee of the call at `site`, before it is hooked: `call rel32`, or
/// through a pointer slot in ELF builds.
fn callee_at(image: &Image<'_>, site: usize) -> Option<usize> {
   let code = image.read(site, 6).or_else(|| image.read(site, 5))?;
   phoenix_hook::x86::call_target(image, code, site).map(|(_, callee)| callee)
}

static ORIG_DM_CHILD: OnceLock<NameChildFn> = OnceLock::new();
static DM_SOME: AtomicUsize = AtomicUsize::new(0);
static DM_USER: AtomicUsize = AtomicUsize::new(0);

/// Points the call adding the recipient's name to a DM row at
/// [`dm_child_detour`], so member decorations follow the name there too, as
/// Vencord's member list setting covers the DM list.
fn install_dm(image: &Image<'static>, row: &desktop::DmRow) {
   let Some(target) = callee_at(image, row.site) else {
      return;
   };
   DM_SOME.store(row.some, Ordering::Release);
   DM_USER.store(row.user, Ordering::Release);
   // SAFETY: `target` is the call's own `Div::child`, stored before the call
   // can reach the detour.
   let _ = ORIG_DM_CHILD.set(unsafe { std::mem::transmute::<usize, NameChildFn>(target) });
   let frame = row.frame.island(phoenix_hook::x86::Abi::of(image).arg(3));
   // SAFETY: as in `install_name`.
   match unsafe { image.hook_call(row.site, &frame, dm_child_detour as *const () as usize) } {
      Ok(_) => log::info!("desktop members: hooked the DM name @ {:#x}", row.site),
      Err(err) => log::warn!("desktop members: DM name hook failed: {err}"),
   }
}

unsafe extern "C" fn dm_child_detour(
   out: *mut c_void,
   div: *mut c_void,
   child: *mut c_void,
   frame: *const u8,
) -> *mut c_void {
   let Some(orig) = ORIG_DM_CHILD.get().copied() else {
      return out;
   };
   // SAFETY: forwards `Div::child`'s own arguments.
   let row = unsafe { orig(out, div, child) };
   if !MEMBERS.active() || row.is_null() || frame.is_null() {
      return row;
   }
   // SAFETY: `frame` is what the DM row's decoded slots are addressed from,
   // and they hold the recipient's `Option<UserId>`, unset for group DMs.
   let user_id = unsafe {
      let slot = |at: &AtomicUsize| {
         frame
            .add(at.load(Ordering::Relaxed))
            .cast::<u64>()
            .read_unaligned()
      };
      if slot(&DM_SOME) == 0 {
         return row;
      }
      slot(&DM_USER)
   };
   decorate(row, user_id, DM_LEAD);
   row
}

/// The member row spaces its children 4 px apart and the DM row's name box
/// does not, so DM decorations add that space themselves.
const DM_LEAD: f32 = 4.0;

/// Points the calls adding the member's name to its row at
/// [`name_child_detour`], so decorations follow the name inside that row. The
/// islands hand the detour the row function's frame or the closure's
/// environment, which leads to the user id.
fn install_name(image: &Image<'static>, name: &desktop::MemberName) {
   CLOSURE_SLOT.store(name.closure_slot.unwrap_or(ENV_IS_FRAME), Ordering::Release);
   ENV_USER_ID.store(name.env, Ordering::Release);
   let frame = name.frame.island(phoenix_hook::x86::Abi::of(image).arg(3));
   for &site in &name.sites {
      let Some(target) = callee_at(image, site) else {
         continue;
      };
      // SAFETY: `target` is the call's own `Div::child`, stored before a call
      // can reach the detour. ELF builds call identical copies of it, which
      // `member_row` checks.
      let _ = ORIG_NAME_CHILD.set(unsafe { std::mem::transmute::<usize, NameChildFn>(target) });
      // SAFETY: runs from `prepare` before Discord threads execute; the island
      // only sets the fourth argument register, which the three-argument
      // `Div::child` does not read.
      match unsafe { image.hook_call(site, &frame, name_child_detour as *const () as usize) } {
         Ok(_) => log::info!("desktop members: hooked the member name @ {site:#x}"),
         Err(err) => log::warn!("desktop members: member name hook failed: {err}"),
      }
   }
}

unsafe extern "C" fn name_child_detour(
   out: *mut c_void,
   div: *mut c_void,
   child: *mut c_void,
   frame: *const u8,
) -> *mut c_void {
   let Some(orig) = ORIG_NAME_CHILD.get().copied() else {
      return out;
   };
   // SAFETY: forwards `Div::child`'s own arguments.
   let row = unsafe { orig(out, div, child) };
   if !MEMBERS.active() || row.is_null() || frame.is_null() {
      return row;
   }
   // SAFETY: `frame` is the closure's environment, or what its decoded slot
   // holding the environment is addressed from; the environment holds a
   // pointer to the member's user id.
   let user_id = unsafe {
      let env = match CLOSURE_SLOT.load(Ordering::Relaxed) {
         ENV_IS_FRAME => frame,
         slot => frame.add(slot).cast::<*const u8>().read_unaligned(),
      };
      if env.is_null() {
         return row;
      }
      let id = env
         .add(ENV_USER_ID.load(Ordering::Relaxed))
         .cast::<*const u64>()
         .read_unaligned();
      if id.is_null() {
         return row;
      }
      id.read_unaligned()
   };
   decorate(row, user_id, 0.0);
   row
}

/// Appends what the member decorations drew for `user_id` to `row`, `lead`
/// pixels after the name.
fn decorate(row: *mut c_void, user_id: u64, lead: f32) {
   if user_id < MIN_SNOWFLAKE {
      return;
   }
   if let Some(lines) = lines_for(user_id) {
      let _ = std::panic::catch_unwind(|| gpui::append_pieces(row, &lines, lead));
   }
}

/// The text decorations drew for `user_id`, queueing them when unknown.
fn lines_for(user_id: u64) -> Option<Vec<gpui::Piece>> {
   let lines = MEMBERS
      .lookup(user_id)?
      .iter()
      .filter(|item| !item.text.is_empty() || !item.icons.is_empty())
      .map(RenderedAccessory::piece)
      .collect::<Vec<_>>();
   (!lines.is_empty()).then_some(lines)
}

#[cfg(target_os = "macos")]
mod arm64 {
   use std::cell::Cell;

   use super::{
      AtomicUsize,
      DM_LEAD,
      Image,
      MEMBERS,
      NameChildFn,
      OnceLock,
      Ordering,
      c_void,
      decorate,
   };

   type DmRowFn = unsafe extern "C" fn(
      *mut c_void,
      *mut c_void,
      *const u8,
      *mut c_void,
      *mut c_void,
   ) -> *mut c_void;
   type DmNameBoxFn =
      unsafe extern "C" fn(*mut c_void, usize, usize, usize, usize, usize, usize) -> *mut c_void;

   static ORIG_MEMBER_NAME: OnceLock<NameChildFn> = OnceLock::new();
   static MEMBER_ENV_USER_ID: AtomicUsize = AtomicUsize::new(0);

   static ORIG_DM_ROW: OnceLock<DmRowFn> = OnceLock::new();
   static ORIG_DM_NAME_BOX: OnceLock<DmNameBoxFn> = OnceLock::new();
   static ORIG_DIV_CHILD_ANY: OnceLock<NameChildFn> = OnceLock::new();
   static DM_PROPS_SOME: AtomicUsize = AtomicUsize::new(0);
   static DM_PROPS_USER: AtomicUsize = AtomicUsize::new(0);

   thread_local! {
      static ACTIVE_DM_USER: Cell<u64> = const { Cell::new(0) };
      static LAST_DM_NAME_PTR: Cell<usize> = const { Cell::new(0) };
   }

   /// Hooks the member name closure and the DM row name box on macOS arm64.
   pub fn install(image: &Image<'static>) {
      match phoenix_sigs::macos::member_row(image) {
         Ok(row) => install_member(image, row),
         Err(err) => log::warn!("desktop members: {err}, skipping"),
      }
      match phoenix_sigs::macos::dm_row(image) {
         Ok(row) => install_dm(image, row),
         Err(err) => log::warn!("desktop members: {err}, skipping the DM list"),
      }
   }

   fn install_member(image: &Image<'static>, row: phoenix_sigs::macos::MemberRow) {
      MEMBER_ENV_USER_ID.store(row.env_user_id, Ordering::Release);
      // SAFETY: called from `prepare` before Discord threads run;
      // `member_name_detour` matches the closure's x86-style sret ABI.
      if let Some(orig) = unsafe {
         crate::hook_sret::<NameChildFn>(
            image,
            |pro| pro.frame,
            row.name_closure,
            member_name_detour as *const () as usize,
            "desktop members: member name hook failed",
         )
      } {
         let _ = ORIG_MEMBER_NAME.set(orig);
         log::info!(
            "desktop members: hooked member name closure @ {:#x} (env +{:#x})",
            row.name_closure,
            row.env_user_id
         );
      }
   }

   fn install_dm(image: &Image<'static>, row: phoenix_sigs::macos::DmRow) {
      DM_PROPS_SOME.store(row.props_some, Ordering::Release);
      DM_PROPS_USER.store(row.props_user, Ordering::Release);
      // SAFETY: called from `prepare` before Discord threads run; each detour
      // matches its target's x86-style sret ABI.
      let hooked = unsafe {
         let Some(orig_row) = crate::hook_sret::<DmRowFn>(
            image,
            |pro| pro.frame,
            row.func,
            dm_row_detour as *const () as usize,
            "desktop members: DM row hook failed",
         ) else {
            return;
         };
         let _ = ORIG_DM_ROW.set(orig_row);
         let Some(orig_box) = crate::hook_sret::<DmNameBoxFn>(
            image,
            |pro| pro.frame,
            row.name_box,
            dm_name_box_detour as *const () as usize,
            "desktop members: DM name box hook failed",
         ) else {
            return;
         };
         let _ = ORIG_DM_NAME_BOX.set(orig_box);
         let Some(orig_child) = crate::hook_sret::<NameChildFn>(
            image,
            |pro| pro.frame,
            row.div_child_any,
            div_child_any_detour as *const () as usize,
            "desktop members: DM child hook failed",
         ) else {
            return;
         };
         let _ = ORIG_DIV_CHILD_ANY.set(orig_child);
         true
      };
      if hooked {
         log::info!(
            "desktop members: hooked DM row @ {:#x} (name_box {:#x}, child {:#x})",
            row.func,
            row.name_box,
            row.div_child_any
         );
      }
   }

   unsafe extern "C" fn member_name_detour(
      out: *mut c_void,
      row: *mut c_void,
      env: *mut c_void,
   ) -> *mut c_void {
      let Some(orig) = ORIG_MEMBER_NAME.get().copied() else {
         return out;
      };
      // SAFETY: forwards `member_name`'s own arguments.
      let result = unsafe { orig(out, row, env) };
      if !MEMBERS.active() || result.is_null() || env.is_null() {
         return result;
      }
      // SAFETY: `env` holds a pointer to the member's `u64` user id at the
      // decoded offset.
      let user_id = unsafe {
         let id_ptr = env
            .cast::<u8>()
            .add(MEMBER_ENV_USER_ID.load(Ordering::Relaxed))
            .cast::<*const u64>()
            .read_unaligned();
         if id_ptr.is_null() {
            return result;
         }
         id_ptr.read_unaligned()
      };
      decorate(result, user_id, 0.0);
      result
   }

   unsafe extern "C" fn dm_row_detour(
      out: *mut c_void,
      a0: *mut c_void,
      props: *const u8,
      a2: *mut c_void,
      a3: *mut c_void,
   ) -> *mut c_void {
      let Some(orig) = ORIG_DM_ROW.get().copied() else {
         return out;
      };
      let user_id = if MEMBERS.active() && !props.is_null() {
         // SAFETY: `props` holds the recipient's `Option<UserId>` at the
         // decoded offsets; `some == 0` for group DMs.
         unsafe {
            let some = props
               .add(DM_PROPS_SOME.load(Ordering::Relaxed))
               .cast::<u64>()
               .read_unaligned();
            if some != 0 {
               props
                  .add(DM_PROPS_USER.load(Ordering::Relaxed))
                  .cast::<u64>()
                  .read_unaligned()
            } else {
               0
            }
         }
      } else {
         0
      };
      let prev_user = ACTIVE_DM_USER.replace(user_id);
      let prev_ptr = LAST_DM_NAME_PTR.replace(0);
      // SAFETY: forwards `dm_row`'s own arguments.
      let res = unsafe { orig(out, a0, props, a2, a3) };
      ACTIVE_DM_USER.set(prev_user);
      LAST_DM_NAME_PTR.set(prev_ptr);
      res
   }

   unsafe extern "C" fn dm_name_box_detour(
      out: *mut c_void,
      a0: usize,
      a1: usize,
      a2: usize,
      a3: usize,
      a4: usize,
      a5: usize,
   ) -> *mut c_void {
      let Some(orig) = ORIG_DM_NAME_BOX.get().copied() else {
         return out;
      };
      // SAFETY: forwards `dm_name_box`'s own arguments.
      let res = unsafe { orig(out, a0, a1, a2, a3, a4, a5) };
      if ACTIVE_DM_USER.get() != 0 && !res.is_null() {
         // SAFETY: `res` is the initialized `AnyElement` whose leading word is
         // its unique `Box<dyn Element>` heap pointer.
         let ptr = unsafe { res.cast::<usize>().read_unaligned() };
         LAST_DM_NAME_PTR.set(ptr);
      }
      res
   }

   unsafe extern "C" fn div_child_any_detour(
      out: *mut c_void,
      div: *mut c_void,
      child: *mut c_void,
   ) -> *mut c_void {
      let Some(orig) = ORIG_DIV_CHILD_ANY.get().copied() else {
         return out;
      };
      let want = LAST_DM_NAME_PTR.get();
      let matched = want != 0
         && !child.is_null()
         // SAFETY: `child` is a live `&AnyElement` passed to `Div::child`.
         && unsafe { child.cast::<usize>().read_unaligned() } == want;
      if matched {
         LAST_DM_NAME_PTR.set(0);
      }
      // SAFETY: forwards `Div::child`'s own arguments.
      let row = unsafe { orig(out, div, child) };
      if matched && !row.is_null() {
         let user_id = ACTIVE_DM_USER.get();
         decorate(row, user_id, DM_LEAD);
      }
      row
   }
}
