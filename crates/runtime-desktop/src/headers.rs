//! Plugin icons after the author's name in message headers
//! (`phoenix.ui.addMessageHeaderDecoration`) on Desktop Phoenix.
//!
//! Headers are Discord's own `Rc<Node>` trees, not GPUI elements. Each display
//! mode's header row adds the name wrapper with one `child_node` call, found by
//! [`desktop::message_header`]; those calls are pointed at [`name_detour`],
//! which adds the decorations' icons as Discord's node SVG leaves right after.
//!
//! The header only knows the message id, so a worker looks its author up in
//! Phoenix's message store once per message.

use std::{
   collections::HashMap,
   ffi::c_void,
   sync::{
      LazyLock,
      OnceLock,
      RwLock,
      mpsc,
   },
};

use phoenix_hook::image::Image;
use phoenix_sigs::{
   desktop,
   index::Index,
   locate::message,
};

use crate::{
   accessories::{
      self,
      invalidate_discord_windows,
   },
   members::{
      HEADERS,
      MIN_SNOWFLAKE,
   },
};

/// `child_node(node, child) -> node`, `Rc<Node>` handles in and out.
type ChildNodeFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void;
/// `svg_new(out, path ptr, path len, size)`, writing a node SVG leaf.
type SvgNewFn = unsafe extern "C" fn(*mut u8, *const u8, usize, f32) -> *mut u8;
/// `push_svg(node, &leaf) -> node`, moving the leaf into a child.
type PushSvgFn = unsafe extern "C" fn(*mut c_void, *mut u8) -> *mut c_void;

/// Room for the leaf, which is 0x38 bytes on builds so far; a larger one turns
/// the feature off.
const LEAF_WORDS: usize = 32;
/// The box each header icon gets, in px. Plugins place the shape inside it
/// with their SVG's viewBox.
const ICON_SIZE: f32 = 24.0;
/// One detour per header builder.
const SITES: usize = desktop::MAX_HEADER_BUILDERS;

pub struct Symbols {
   child_node: ChildNodeFn,
   svg_new:    SvgNewFn,
   push_svg:   PushSvgFn,
   svg_color:  usize,
   /// `[frame+slot]` holds the message id at each site.
   slots:      Vec<usize>,
}

static SYMBOLS: OnceLock<Symbols> = OnceLock::new();

/// Hooks the header builders' name calls, from `DllMain`.
pub fn install(image: &Image<'static>, found: Result<Located, String>) {
   let (symbols, sites, frame) = match found {
      Ok(found) => found,
      Err(err) => {
         log::warn!("desktop headers: {err}, skipping");
         return;
      },
   };
   let detours: [usize; SITES] = [
      name_detour::<0> as *const () as usize,
      name_detour::<1> as *const () as usize,
      name_detour::<2> as *const () as usize,
   ];
   let child_node = symbols.child_node as usize;
   if SYMBOLS.set(symbols).is_err() {
      return;
   }
   let frame = frame.island(phoenix_hook::x86::Abi::of(image).arg(2));
   for (site, detour) in sites.into_iter().zip(detours) {
      // SAFETY: runs from `prepare` before Discord threads execute; the island
      // only sets the third argument register, which the two-argument
      // `child_node` does not read, and the detour calls `child_node` itself,
      // stored above.
      match unsafe { image.hook_call(site, &frame, detour) } {
         Ok(target) if target == child_node => {
            log::info!("desktop headers: hooked the header name @ {site:#x}");
         },
         Ok(target) => log::warn!("desktop headers: {site:#x} called {target:#x}"),
         Err(err) => log::warn!("desktop headers: header name hook failed: {err}"),
      }
   }
}

/// The symbols, the call adding the name in each header builder, and what the
/// detours read the message id from.
type Located = (Symbols, Vec<usize>, desktop::Frame);

/// Finds [`Located`]. Runs before any hook goes in.
pub fn locate(image: &Image<'_>, ix: &Index<'_>) -> Result<Located, String> {
   let row = message::message_row(ix)?;
   let body = message::message_body(ix, row.func)?;
   let header = desktop::message_header(image, body.func)?;
   if header.sites.len() > SITES {
      return Err(format!("{} header name calls", header.sites.len()));
   }
   let svg = header.svg;
   if svg.size > LEAF_WORDS * 8 {
      return Err(format!("the node SVG leaf is {:#x} bytes", svg.size));
   }
   // SAFETY: decoded from Discord's own calls with these signatures: two
   // handles; `out`, path and the float size; the handle and the leaf's
   // address.
   let symbols = unsafe {
      Symbols {
         child_node: std::mem::transmute::<usize, ChildNodeFn>(header.child_node),
         svg_new:    std::mem::transmute::<usize, SvgNewFn>(svg.new),
         push_svg:   std::mem::transmute::<usize, PushSvgFn>(svg.push),
         svg_color:  svg.color,
         slots:      header.sites.iter().map(|site| site.slot).collect(),
      }
   };
   let sites = header.sites.iter().map(|site| site.site).collect();
   Ok((symbols, sites, header.frame))
}

/// Message id to author id, `0` while the lookup is pending or found nothing.
static AUTHORS: LazyLock<RwLock<HashMap<u64, u64>>> = LazyLock::new(|| RwLock::new(HashMap::new()));
static RESOLVER: OnceLock<mpsc::Sender<u64>> = OnceLock::new();
const MAX_AUTHORS: usize = 8192;

/// The author of `message_id`, queueing the store lookup when unknown.
fn author_of(message_id: u64) -> Option<u64> {
   if let Some(&author) = AUTHORS.read().ok()?.get(&message_id) {
      return (author != 0).then_some(author);
   }
   let queue = AUTHORS.write().is_ok_and(|mut map| {
      if map.len() > MAX_AUTHORS {
         map.clear();
      }
      map.insert(message_id, 0).is_none()
   });
   if queue {
      let _ = resolver().send(message_id);
   }
   None
}

fn resolver() -> &'static mpsc::Sender<u64> {
   RESOLVER.get_or_init(|| {
      let (tx, rx) = mpsc::channel::<u64>();
      let _ = std::thread::Builder::new()
         .name("sunbird-authors".to_owned())
         .spawn(move || {
            while let Ok(message_id) = rx.recv() {
               let Some(author) = crate::js::ui::cached_author(message_id) else {
                  continue;
               };
               if let Ok(mut map) = AUTHORS.write() {
                  map.insert(message_id, author);
               }
               // Queues the decorations, or redraws with ones already known.
               if HEADERS.lookup(author).is_some() {
                  invalidate_discord_windows();
               }
            }
         });
      tx
   })
}

/// The icons the header decorations drew for `message_id`'s author, queueing
/// what is unknown.
fn icons_for_message(message_id: u64) -> Vec<(&'static str, Option<u32>)> {
   if message_id < MIN_SNOWFLAKE {
      return Vec::new();
   }
   author_of(message_id)
      .and_then(|author| HEADERS.lookup(author))
      .unwrap_or_default()
      .into_iter()
      .flat_map(|item| item.icons)
      .collect()
}

/// The icons the header decorations drew for the author of the message at
/// `frame`, queueing what is unknown.
fn icons(symbols: &Symbols, site: usize, frame: *const u8) -> Vec<(&'static str, Option<u32>)> {
   let Some(&slot) = symbols.slots.get(site) else {
      return Vec::new();
   };
   // SAFETY: the builder keeps the message id at `[frame+slot]` at the call.
   let message_id = unsafe { frame.add(slot).cast::<u64>().read_unaligned() };
   icons_for_message(message_id)
}

fn append_icons(
   mut node: *mut c_void,
   svg_new: SvgNewFn,
   push_svg: PushSvgFn,
   svg_color: usize,
   icons: Vec<(&'static str, Option<u32>)>,
) -> *mut c_void {
   for (path, color) in icons {
      let mut leaf = [0u64; LEAF_WORDS];
      let leaf = leaf.as_mut_ptr().cast::<u8>();
      // SAFETY: `leaf` has room for the node SVG leaf; Discord copies `path`
      // into its own string, and `push_svg` moves the leaf into the node and
      // returns the node's handle, which may be a fresh clone.
      unsafe {
         svg_new(leaf, path.as_ptr(), path.len(), ICON_SIZE);
         if let Some(argb) = color {
            leaf.add(svg_color).cast::<u32>().write_unaligned(1);
            leaf
               .add(svg_color + 4)
               .cast::<u32>()
               .write_unaligned(accessories::argb_to_rgba(argb));
         }
         node = push_svg(node, leaf);
      }
      if node.is_null() {
         break;
      }
   }
   node
}

/// `child_node` adding the name wrapper, then the decorations' icons. The
/// island hands it what the builder's frame slots are addressed from as
/// `frame`.
unsafe extern "C" fn name_detour<const SITE: usize>(
   node: *mut c_void,
   child: *mut c_void,
   frame: *const u8,
) -> *mut c_void {
   let Some(symbols) = SYMBOLS.get() else {
      return node;
   };
   // SAFETY: forwards `child_node`'s own arguments.
   let node = unsafe { (symbols.child_node)(node, child) };
   if !HEADERS.active() || node.is_null() || frame.is_null() {
      return node;
   }
   let Ok(icons) = std::panic::catch_unwind(|| icons(symbols, SITE, frame)) else {
      return node;
   };
   append_icons(
      node,
      symbols.svg_new,
      symbols.push_svg,
      symbols.svg_color,
      icons,
   )
}

/// Message header decorations on macOS arm64
/// ([`phoenix_sigs::macos::message_header`]).
#[cfg(target_os = "macos")]
pub mod arm64 {
   use std::{
      cell::Cell,
      ffi::c_void,
      sync::OnceLock,
   };

   use phoenix_hook::image::{
      Image,
      sret_caller,
   };

   use super::{
      ChildNodeFn,
      HEADERS,
      LEAF_WORDS,
      PushSvgFn,
      SvgNewFn,
      accessories,
      append_icons,
      icons_for_message,
   };

   type NameProducerFn = unsafe extern "C" fn(
      usize,
      usize,
      usize,
      usize,
      usize,
      usize,
      usize,
      usize,
      f64,
      f64,
      f64,
      f64,
      f64,
      f64,
      f64,
      f64,
      usize,
      usize,
      usize,
      usize,
      usize,
      usize,
      usize,
      usize,
   ) -> *mut c_void;

   struct Symbols {
      orig_name:  NameProducerFn,
      orig_child: ChildNodeFn,
      svg_new:    SvgNewFn,
      push_svg:   PushSvgFn,
      svg_color:  usize,
   }

   static SYMBOLS: OnceLock<Symbols> = OnceLock::new();

   std::thread_local! {
      static LAST_NAME_NODE: Cell<usize> = const { Cell::new(0) };
   }

   /// Clears any pending name node so an unmatched row cannot leak its pointer
   /// into a later row's `child_node` call.
   pub fn clear_last_name_node() {
      LAST_NAME_NODE.set(0);
   }

   pub fn install(image: &Image<'static>) {
      let header = match phoenix_sigs::macos::message_header(image) {
         Ok(header) => header,
         Err(err) => {
            log::warn!("desktop headers: {err}, skipping");
            return;
         },
      };
      if header.svg.size > LEAF_WORDS * 8 {
         log::warn!(
            "desktop headers: the node SVG leaf is {:#x} bytes, skipping",
            header.svg.size
         );
         return;
      }
      let Some(svg_new_thunk) = sret_caller(header.svg.new) else {
         log::warn!("desktop headers: no memory for svg_new thunk");
         return;
      };
      // SAFETY: runs from `prepare` before Discord threads execute.
      let Some(orig_name) = (unsafe {
         crate::hook::<NameProducerFn>(
            image,
            |pro| pro.frame,
            header.name_producer,
            name_producer_detour as *const () as usize,
            "desktop headers: name producer hook failed",
         )
      }) else {
         return;
      };
      // SAFETY: runs from `prepare` before Discord threads execute.
      let Some(orig_child) = (unsafe {
         crate::hook::<ChildNodeFn>(
            image,
            |pro| pro.frame,
            header.child_node,
            child_node_detour as *const () as usize,
            "desktop headers: child_node hook failed",
         )
      }) else {
         return;
      };
      // SAFETY: `sret_caller` thunk and `push_svg` match Discord's signatures.
      let symbols = unsafe {
         Symbols {
            orig_name,
            orig_child,
            svg_new: std::mem::transmute::<usize, SvgNewFn>(svg_new_thunk),
            push_svg: std::mem::transmute::<usize, PushSvgFn>(header.svg.push),
            svg_color: header.svg.color,
         }
      };
      let _ = SYMBOLS.set(symbols);
      log::info!(
         "desktop headers: hooked name @ {:#x} and child_node @ {:#x}",
         header.name_producer,
         header.child_node
      );
   }

   #[allow(clippy::too_many_arguments)]
   unsafe extern "C" fn name_producer_detour(
      a0: usize,
      a1: usize,
      a2: usize,
      a3: usize,
      a4: usize,
      a5: usize,
      a6: usize,
      a7: usize,
      f0: f64,
      f1: f64,
      f2: f64,
      f3: f64,
      f4: f64,
      f5: f64,
      f6: f64,
      f7: f64,
      s0: usize,
      s1: usize,
      s2: usize,
      s3: usize,
      s4: usize,
      s5: usize,
      s6: usize,
      s7: usize,
   ) -> *mut c_void {
      let Some(symbols) = SYMBOLS.get() else {
         return std::ptr::null_mut();
      };
      // SAFETY: forwards every register and stack word to the original builder.
      let ret = unsafe {
         (symbols.orig_name)(
            a0, a1, a2, a3, a4, a5, a6, a7, f0, f1, f2, f3, f4, f5, f6, f7, s0, s1, s2, s3, s4, s5,
            s6, s7,
         )
      };
      if HEADERS.active() && !ret.is_null() {
         LAST_NAME_NODE.set(ret as usize);
      }
      ret
   }

   unsafe extern "C" fn child_node_detour(node: *mut c_void, child: *mut c_void) -> *mut c_void {
      let Some(symbols) = SYMBOLS.get() else {
         return node;
      };
      // SAFETY: forwards `child_node`'s own arguments.
      let node = unsafe { (symbols.orig_child)(node, child) };
      let last = LAST_NAME_NODE.get();
      if last == 0 || child as usize != last {
         return node;
      }
      LAST_NAME_NODE.set(0);
      if !HEADERS.active() || node.is_null() {
         return node;
      }
      let message_id = accessories::current_rendering_message_id();
      let Ok(icons) = std::panic::catch_unwind(|| icons_for_message(message_id)) else {
         return node;
      };
      append_icons(
         node,
         symbols.svg_new,
         symbols.push_svg,
         symbols.svg_color,
         icons,
      )
   }
}
