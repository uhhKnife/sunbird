//! Native GPUI message context menu (`phoenix.ui.addMessageAction`) for
//! Desktop Phoenix.
//!
//! Hooks Discord's `MessageContextMenu` item builder (called by both the
//! right-click context menu and the `...` message action popover), reads
//! `message_id` and `channel_id` from the input before Discord consumes it,
//! and appends a native `MenuItem::Separator` plus each visible plugin
//! `MenuItem::Action` with a native `Rc<dyn Fn>` click callback.

use std::{
   collections::{
      HashMap,
      VecDeque,
   },
   ffi::c_void,
   ptr,
   sync::{
      LazyLock,
      Mutex,
      OnceLock,
      PoisonError,
      RwLock,
      atomic::{
         AtomicU64,
         AtomicUsize,
         Ordering,
      },
      mpsc,
   },
};

use phoenix_hook::image::Image;
use phoenix_sigs::desktop::{
   self,
   MenuLayout,
   SubmenuLayout,
   layout,
};

use crate::{
   double_click,
   gpui::{
      self,
      RcFnVtbl,
      Scratch,
      SharedString,
   },
};

/// `Vec<MenuItem>` in Discord's Rust ABI (`[cap, ptr, len]`).
#[repr(C)]
pub struct RawMenuVec {
   cap: usize,
   ptr: *mut c_void,
   len: usize,
}

type RawMenuItem = Scratch<{ layout::SCRATCH_CAP }>;

type BuildMenuFn = unsafe extern "C" fn(
   sret: *mut RawMenuVec,
   input: *const c_void,
   a2: usize,
   a3: usize,
   s0: u64,
   s1: u64,
   s2: u64,
   s3: u64,
) -> *mut RawMenuVec;

type PropsNewFn = unsafe extern "C" fn(*mut u8, *const SharedString, u8, u8) -> *mut u8;
type WithIdFn =
   unsafe extern "C" fn(*mut RawMenuItem, *mut RawMenuItem, *const u8, usize) -> *mut RawMenuItem;
type WithIconFn = unsafe extern "C" fn(*mut RawMenuItem, *mut RawMenuItem, u16) -> *mut RawMenuItem;
type WithColorFn = unsafe extern "C" fn(*mut RawMenuItem, *mut RawMenuItem, u8) -> *mut RawMenuItem;
type VecPushFn = unsafe extern "C" fn(*mut RawMenuVec, *mut RawMenuItem);

struct MenuSymbols {
   orig_build:        BuildMenuFn,
   msg_ptr_offset:    usize,
   msg_id_offset:     usize,
   channel_id_offset: usize,
   props_new:         PropsNewFn,
   with_id:           WithIdFn,
   with_icon:         WithIconFn,
   with_color:        WithColorFn,
   vec_push:          VecPushFn,
   layout:            MenuLayout,
   /// Where `with_id` keeps a short id inline, its length byte first.
   id_offset:         Option<usize>,
   /// Without it, plugin submenus show their items inline.
   submenu:           Option<SubmenuLayout>,
}

// SAFETY: function pointers and plain struct offsets into `Discord.exe`.
unsafe impl Send for MenuSymbols {}
unsafe impl Sync for MenuSymbols {}

static MENU_SYMS: OnceLock<MenuSymbols> = OnceLock::new();

/// Snapshot of one registered `phoenix.ui.addMessageAction` item, read on the
/// GPUI thread when a message context menu opens.
#[derive(Clone, Debug)]
pub struct ActionMeta {
   pub id:          u64,
   pub label:       String,
   pub icon:        Option<String>,
   pub danger:      bool,
   pub priority:    i32,
   pub has_visible: bool,
   /// The action whose submenu this one sits in.
   pub parent:      Option<u64>,
}

static ACTIVE_COUNT: AtomicUsize = AtomicUsize::new(0);
static ACTIONS: LazyLock<RwLock<Vec<ActionMeta>>> = LazyLock::new(|| RwLock::new(Vec::new()));

/// Maps an opaque click token stored inside `RcInner::action_id` to the
/// `(action_id, message_id, channel_id)` to invoke when the user clicks it.
#[derive(Clone, Copy)]
struct PendingClick {
   action:  u64,
   message: u64,
   channel: u64,
}

const MAX_PENDING_CLICKS: usize = 512;

struct ClickTable<T = PendingClick> {
   order: VecDeque<u64>,
   map:   HashMap<u64, T>,
}

impl<T> ClickTable<T> {
   /// Keeps `value` under a fresh token, forgetting the oldest past
   /// [`MAX_PENDING_CLICKS`].
   fn insert(&mut self, value: T) -> u64 {
      let token = NEXT_CLICK_TOKEN.fetch_add(1, Ordering::Relaxed);
      while self.order.len() >= MAX_PENDING_CLICKS {
         if let Some(old) = self.order.pop_front() {
            self.map.remove(&old);
         }
      }
      self.order.push_back(token);
      self.map.insert(token, value);
      token
   }
}

static NEXT_CLICK_TOKEN: AtomicU64 = AtomicU64::new(1);
static CLICKS: LazyLock<Mutex<ClickTable>> = LazyLock::new(|| {
   Mutex::new(ClickTable {
      order: VecDeque::new(),
      map:   HashMap::new(),
   })
});
static WORKER_TX: OnceLock<mpsc::Sender<PendingClick>> = OnceLock::new();

/// A plugin submenu's children, found again when its builder runs.
#[derive(Clone, Copy)]
struct PendingSubmenu {
   parent:  u64,
   message: u64,
   channel: u64,
}

static SUBMENUS: LazyLock<Mutex<ClickTable<PendingSubmenu>>> = LazyLock::new(|| {
   Mutex::new(ClickTable {
      order: VecDeque::new(),
      map:   HashMap::new(),
   })
});

static SUBMENU_VTBL: RcFnVtbl = RcFnVtbl {
   drop_in_place: ptr::null(),
   size:          size_of::<u64>(),
   align:         align_of::<u64>(),
   call_once:     build_submenu as *const c_void,
   call_mut:      build_submenu as *const c_void,
   call:          build_submenu as *const c_void,
   extra:         ptr::null(),
};

static MENU_ACTION_VTBL: RcFnVtbl = RcFnVtbl {
   drop_in_place: ptr::null(),
   size:          size_of::<u64>(),
   align:         align_of::<u64>(),
   call_once:     menu_action_callback as *const c_void,
   call_mut:      menu_action_callback as *const c_void,
   call:          menu_action_callback as *const c_void,
   extra:         ptr::null(),
};

/// Updates the menu-thread snapshot of registered `addMessageAction` entries.
pub fn sync_actions(mut items: Vec<ActionMeta>) {
   items.sort_by_key(|item| (item.priority, item.id));
   let len = items.len();
   if let Ok(mut guard) = ACTIONS.write() {
      *guard = items;
   }
   ACTIVE_COUNT.store(len, Ordering::Release);
   if len > 0 {
      ensure_worker();
   }
}

fn ensure_worker() -> &'static mpsc::Sender<PendingClick> {
   WORKER_TX.get_or_init(|| {
      let (tx, rx) = mpsc::channel::<PendingClick>();
      let _ = std::thread::Builder::new()
         .name("sunbird-msg-act".to_owned())
         .spawn(move || {
            while let Ok(click) = rx.recv() {
               if let Some(engine) = phoenix_runtime::engine() {
                  crate::js::ui::invoke_message_action(
                     &engine,
                     click.action,
                     click.message,
                     click.channel,
                  );
               }
            }
         });
      tx
   })
}

fn register_click(click: PendingClick) -> u64 {
   CLICKS
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .insert(click)
}

unsafe extern "C" fn menu_action_callback(
   data: *const u64,
   _event: *const c_void,
   _window: *mut c_void,
   _app: *mut c_void,
) {
   if data.is_null() {
      return;
   }
   // SAFETY: `data` points to `RcInner::action_id` allocated by `alloc_rc_u64`.
   let token = unsafe { ptr::read_unaligned(data) };
   let click = CLICKS
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .map
      .get(&token)
      .copied();
   if let Some(click) = click {
      let _ = ensure_worker().send(click);
   }
}

/// Maps well-known mobile/plugin icon names to Desktop Phoenix's verified
/// Mana icon enum values (observed in `MessageContextMenu`).
fn map_icon(icon: Option<&str>) -> Option<u16> {
   let icon = icon?;
   if icon.contains("delete") || icon.contains("trash") {
      Some(0x280)
   } else if icon.contains("copy_id") || icon.contains("id") {
      Some(0x15B)
   } else if icon.contains("link") {
      Some(0x177)
   } else if icon.contains("copy") || icon.contains("angle_brackets") || icon.contains("code") {
      Some(0x099)
   } else {
      None
   }
}

/// Locates and hooks `MessageContextMenu` from `DllMain`.
pub fn install(image: &Image<'static>) {
   let menu = match desktop::message_context_menu(image) {
      Ok(menu) => menu,
      Err(err) => {
         log::warn!("desktop context menu: {err}, skipping");
         return;
      },
   };

   let pro = desktop::Prologues::of(phoenix_hook::x86::Abi::of(image)).row;
   // SAFETY: runs from `prepare` before Discord threads execute;
   // `build_context_menu_detour` matches `MessageContextMenu`'s 8-arg sret ABI.
   let trampoline = match unsafe {
      image.hook_entry(
         menu.build_fn,
         pro.pattern,
         pro.len,
         build_context_menu_detour as *const () as usize,
      )
   } {
      Ok(trampoline) => trampoline,
      Err(err) => {
         log::warn!("desktop context menu: hook failed: {err}");
         return;
      },
   };

   // SAFETY: every address was validated by `desktop::message_context_menu`.
   let syms = unsafe {
      MenuSymbols {
         orig_build:        std::mem::transmute::<usize, BuildMenuFn>(trampoline),
         msg_ptr_offset:    menu.msg_ptr_offset,
         msg_id_offset:     menu.msg_id_offset,
         channel_id_offset: menu.channel_id_offset,
         props_new:         std::mem::transmute::<usize, PropsNewFn>(menu.props_new),
         with_id:           std::mem::transmute::<usize, WithIdFn>(menu.with_id),
         with_icon:         std::mem::transmute::<usize, WithIconFn>(menu.with_icon),
         with_color:        std::mem::transmute::<usize, WithColorFn>(menu.with_color),
         vec_push:          std::mem::transmute::<usize, VecPushFn>(menu.vec_push),
         layout:            menu.layout,
         id_offset:         None,
         submenu:           desktop::submenu_layout(image)
            .inspect_err(|err| log::warn!("desktop context menu: {err}, submenus show inline"))
            .ok(),
      }
   };
   let syms = MenuSymbols {
      id_offset: inline_id_offset(&syms),
      ..syms
   };
   let _ = MENU_SYMS.set(syms);
   log::info!(
      "desktop context menu: hooked MessageContextMenu @ {:#x} (msg +{:#x}, id +{:#x}, ch +{:#x}) \
       {:x?}",
      menu.build_fn,
      menu.msg_ptr_offset,
      menu.msg_id_offset,
      menu.channel_id_offset,
      menu.layout,
   );
}

#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn build_context_menu_detour(
   sret: *mut RawMenuVec,
   input: *const c_void,
   a2: usize,
   a3: usize,
   s0: u64,
   s1: u64,
   s2: u64,
   s3: u64,
) -> *mut RawMenuVec {
   let Some(syms) = MENU_SYMS.get() else {
      return sret;
   };

   // Read `message_id` and `channel_id` BEFORE calling `orig_build`, because
   // `MessageContextMenu` takes `input` by value and drops it before returning.
   let wanted = ACTIVE_COUNT.load(Ordering::Acquire) > 0 || double_click::pending();
   let (message_id, channel_id) = if wanted && !input.is_null() {
      // SAFETY: `input` is a live `MessageContextMenuInput`; offsets were
      // decoded from `MessageContextMenu` and its permission check callee.
      unsafe {
         let bytes = input.cast::<u8>();
         let mid = bytes.add(syms.msg_id_offset).cast::<u64>().read_unaligned();
         let msg_ptr = bytes
            .add(syms.msg_ptr_offset)
            .cast::<*const u8>()
            .read_unaligned();
         let cid = if msg_ptr.is_null() {
            0
         } else {
            remember_message(msg_ptr, mid);
            msg_ptr
               .add(syms.channel_id_offset)
               .cast::<u64>()
               .read_unaligned()
         };
         (mid, cid)
      }
   } else {
      (0, 0)
   };

   // SAFETY: forwards all arguments verbatim to the original menu builder.
   let out = unsafe { (syms.orig_build)(sret, input, a2, a3, s0, s1, s2, s3) };

   if !sret.is_null()
      && let Some(item) = double_click::take_press(message_id)
   {
      let _ = std::panic::catch_unwind(|| {
         press_item(syms, sret, &item, a3 as *mut c_void, s2 as *mut c_void);
      });
   }

   if message_id == 0 || sret.is_null() || ACTIVE_COUNT.load(Ordering::Acquire) == 0 {
      return out;
   }

   let _ = std::panic::catch_unwind(|| {
      append_plugin_actions(syms, sret, message_id, channel_id);
   });
   out
}

/// The JSON of the message the last menu opened on, read from Discord's memory
/// while the menu's input still holds it.
static MENU_MESSAGE: Mutex<Option<(u64, std::time::Instant, String)>> = Mutex::new(None);
/// GPUI rebuilds an open menu every frame, so its message is serialized again
/// only past this age, which still catches an edit before the next menu.
const MENU_MESSAGE_FRESH: std::time::Duration = std::time::Duration::from_millis(500);

/// Serializes the message at `message` for the menu built for it.
///
/// # Safety
///
/// `message` points to the live `Message` the menu is built for.
unsafe fn remember_message(message: *const u8, id: u64) {
   if MENU_MESSAGE
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .as_ref()
      .is_some_and(|(held, at, _)| *held == id && at.elapsed() < MENU_MESSAGE_FRESH)
   {
      return;
   }
   // SAFETY: the caller's `message` is live for this call.
   if let Some(json) = unsafe { crate::message::json(message, id) } {
      *MENU_MESSAGE.lock().unwrap_or_else(PoisonError::into_inner) =
         Some((id, std::time::Instant::now(), json));
   }
}

/// The JSON of message `id`, when the last menu was opened on it.
pub fn menu_message(id: u64) -> Option<String> {
   let held = MENU_MESSAGE.lock().unwrap_or_else(PoisonError::into_inner);
   let json = held
      .as_ref()
      .filter(|(held, ..)| *held == id)
      .map(|(.., json)| json.clone());
   drop(held);
   json
}

fn append_plugin_actions(
   syms: &MenuSymbols,
   vec: *mut RawMenuVec,
   message_id: u64,
   channel_id: u64,
) {
   let actions: Vec<ActionMeta> = ACTIONS
      .read()
      .map_or_else(|_| Vec::new(), |guard| guard.clone());
   if actions.is_empty() {
      return;
   }

   let visible: Vec<&ActionMeta> = actions
      .iter()
      .filter(|action| action.parent.is_none())
      .filter(|action| {
         if !action.has_visible {
            return true;
         }
         phoenix_runtime::engine().is_none_or(|engine| {
            crate::js::ui::check_action_visible(&engine, action.id, message_id, channel_id)
         })
      })
      .collect();
   if visible.is_empty() {
      return;
   }

   // Push a native separator first if the menu already has Discord's own items.
   // SAFETY: `vec` is the live `Vec<MenuItem>` just returned by `orig_build`.
   let has_existing = unsafe { (*vec).len > 0 };
   if has_existing {
      let mut sep = RawMenuItem::zeroed();
      sep.put(0, layout::MENU_ITEM_SEPARATOR_TAG);
      // SAFETY: `vec_push` copies one `MenuItem`, which fits `sep`.
      unsafe { (syms.vec_push)(vec, &raw mut sep) };
   }

   for action in visible {
      let mut children = actions
         .iter()
         .filter(|child| child.parent == Some(action.id))
         .peekable();
      let items: Vec<RawMenuItem> = match (children.peek().is_some(), syms.submenu) {
         (true, Some(submenu)) => {
            submenu_item(syms, &submenu, action, message_id, channel_id)
               .into_iter()
               .collect()
         },
         // Without one of Discord's submenus to copy, the children go flat.
         (true, None) => {
            children
               .filter_map(|child| action_item(syms, child, message_id, channel_id))
               .collect()
         },
         (false, _) => {
            action_item(syms, action, message_id, channel_id)
               .into_iter()
               .collect()
         },
      };
      for mut item in items {
         // SAFETY: `vec_push` copies one `MenuItem`, which fits `item`.
         unsafe { (syms.vec_push)(vec, &raw mut item) };
      }
   }
}

/// Fills in the props, id, icon and danger color of `item`, whose variant
/// fields are set.
fn finish_item(
   syms: &MenuSymbols,
   mut item: RawMenuItem,
   props: usize,
   action: &ActionMeta,
) -> RawMenuItem {
   let label_ss = SharedString::from_str(&action.label);
   let id_str = gpui::intern_str(&format!("sunbird-msg-action-{}", action.id));
   // SAFETY: `props_new` fills `props_size` bytes at `props`, inside the item;
   // the builders take the item by value and return it through buffers that
   // fit it.
   unsafe {
      (syms.props_new)(item.as_mut_ptr().add(props), &raw const label_ss, 0, 0);

      let mut next = RawMenuItem::zeroed();
      (syms.with_id)(&raw mut next, &raw mut item, id_str.as_ptr(), id_str.len());
      let mut item = next;

      if let Some(icon_id) = map_icon(action.icon.as_deref()) {
         let mut next = RawMenuItem::zeroed();
         (syms.with_icon)(&raw mut next, &raw mut item, icon_id);
         item = next;
      }

      if action.danger {
         let mut next = RawMenuItem::zeroed();
         (syms.with_color)(&raw mut next, &raw mut item, 2);
         item = next;
      }
      item
   }
}

/// A native `MenuItem::Action` with our `Rc<dyn Fn>` click handler, at the
/// offsets `sigs` decoded.
fn action_item(
   syms: &MenuSymbols,
   action: &ActionMeta,
   message: u64,
   channel: u64,
) -> Option<RawMenuItem> {
   let token = register_click(PendingClick {
      action: action.id,
      message,
      channel,
   });
   let rc_ptr = gpui::alloc_rc_u64(token)?;
   let at = &syms.layout;
   let mut item = RawMenuItem::zeroed();
   item.put(0, at.action_tag);
   item.put(at.on_click_tag, 0u64);
   item.put(at.on_click, rc_ptr);
   item.put(at.on_click + 8, &raw const MENU_ACTION_VTBL);
   Some(finish_item(syms, item, at.props, action))
}

/// A native submenu whose builder lists `action`'s children when it opens.
fn submenu_item(
   syms: &MenuSymbols,
   submenu: &SubmenuLayout,
   action: &ActionMeta,
   message: u64,
   channel: u64,
) -> Option<RawMenuItem> {
   if submenu.props_size != syms.layout.props_size {
      return None;
   }
   let token = SUBMENUS
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .insert(PendingSubmenu {
         parent: action.id,
         message,
         channel,
      });
   let rc_ptr = gpui::alloc_rc_u64(token)?;
   let mut item = RawMenuItem::zeroed();
   item.put(0, submenu.tag);
   item.put(submenu.builder, rc_ptr);
   item.put(submenu.builder + 8, &raw const SUBMENU_VTBL);
   item.put(submenu.kind, submenu.kind_value);
   Some(finish_item(syms, item, submenu.props, action))
}

/// A plugin submenu's builder, `fn(&self) -> Vec<MenuItem>`, which Discord
/// runs when the submenu opens.
unsafe extern "C" fn build_submenu(out: *mut RawMenuVec, data: *const u64) -> *mut RawMenuVec {
   if out.is_null() {
      return out;
   }
   // SAFETY: Discord passes the return slot, written before anything else.
   unsafe {
      out.write(RawMenuVec {
         cap: 0,
         ptr: ptr::without_provenance_mut(align_of::<u64>()),
         len: 0,
      });
   }
   let _ = std::panic::catch_unwind(|| {
      let (Some(syms), false) = (MENU_SYMS.get(), data.is_null()) else {
         return;
      };
      // SAFETY: `data` points to the token `alloc_rc_u64` stored.
      let token = unsafe { ptr::read_unaligned(data) };
      let Some(pending) = SUBMENUS
         .lock()
         .unwrap_or_else(PoisonError::into_inner)
         .map
         .get(&token)
         .copied()
      else {
         return;
      };
      let actions: Vec<ActionMeta> = ACTIONS
         .read()
         .map_or_else(|_| Vec::new(), |guard| guard.clone());
      for child in actions
         .iter()
         .filter(|child| child.parent == Some(pending.parent))
      {
         if let Some(mut item) = action_item(syms, child, pending.message, pending.channel) {
            // SAFETY: `out` is the empty `Vec<MenuItem>` written above, grown
            // by Discord's own push.
            unsafe { (syms.vec_push)(out, &raw mut item) };
         }
      }
   });
   out
}

/// Finds where `with_id` stores a short id by giving one to a blank action
/// item. The id moves with the item's variant.
fn inline_id_offset(syms: &MenuSymbols) -> Option<usize> {
   const PROBE: &[u8] = b"zq";
   let mut blank = RawMenuItem::zeroed();
   blank.put(0, syms.layout.action_tag);
   let mut named = RawMenuItem::zeroed();
   // SAFETY: `with_id` reads one item and writes one into buffers that fit
   // it. A two-byte id stays inline, so `named` owns nothing to free.
   unsafe { (syms.with_id)(&raw mut named, &raw mut blank, PROBE.as_ptr(), PROBE.len()) };
   // SAFETY: `named` is `SCRATCH_CAP` bytes, which `layout.size` fits.
   let bytes = unsafe { std::slice::from_raw_parts(named.as_mut_ptr(), syms.layout.size) };
   bytes
      .windows(PROBE.len() + 1)
      .position(|window| window[0] as usize == PROBE.len() && &window[1..] == PROBE)
}

/// Runs the click handler of the item with id `id` in the menu `vec`, with
/// the builder's window and app. Pressing an item inside the builder leaves
/// the menu unshown, the same as a click on it.
fn press_item(
   syms: &MenuSymbols,
   vec: *mut RawMenuVec,
   id: &str,
   window: *mut c_void,
   app: *mut c_void,
) {
   type CallFn = unsafe extern "C" fn(*const u8, *const u8, *mut c_void, *mut c_void);

   let (Some(id_at), Ok(len)) = (syms.id_offset, u8::try_from(id.len())) else {
      return;
   };
   let at = &syms.layout;
   // SAFETY: `vec` is the `Vec<MenuItem>` the builder just returned, items
   // `at.size` bytes apart.
   let items = unsafe { std::slice::from_raw_parts((*vec).ptr.cast::<u8>(), (*vec).len * at.size) };
   let Some(item) = items.chunks_exact(at.size).find(|item| {
      item.get(id_at) == Some(&len)
         && item.get(id_at + 1..id_at + 1 + id.len()) == Some(id.as_bytes())
   }) else {
      log::warn!("double click: the menu has no {id:?}");
      return;
   };
   let word = |offset: usize| {
      item.get(offset..offset + 8).map_or(0, |bytes| {
         usize::from_le_bytes(bytes.try_into().unwrap_or_default())
      })
   };
   let (rc, vtbl) = (word(at.on_click), word(at.on_click + 8) as *const RcFnVtbl);
   if word(0) as u64 != at.action_tag || word(at.on_click_tag) != 0 || rc == 0 || vtbl.is_null() {
      return;
   }
   // The handler takes the app behind one more pointer than the builder gets
   // it, and no event. Passing the builder's app directly segfaults.
   let mut app = app;
   // SAFETY: an `Rc<dyn Fn>` Discord built, whose value follows the two counts
   // at the vtable's alignment.
   unsafe {
      let align = (*vtbl).align.max(1);
      let value = (rc + 16usize.div_ceil(align) * align) as *const u8;
      let call = std::mem::transmute::<*const c_void, CallFn>((*vtbl).call);
      call(value, ptr::null(), window, (&raw mut app).cast());
   }
}
