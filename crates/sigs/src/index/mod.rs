//! One query interface over every Discord binary.
//!
//! Desktop Phoenix on Windows, Linux and macOS is one Rust tree, and so are
//! the Android and iOS hosts. A locator written against what that source
//! forces into the binary (string literals, panic [`Location`]s, tracing
//! callsites, the call graph) then runs on every build of the family, and only
//! the last step, reading an offset or immediate out of an instruction, sees
//! the ISA, through [`Op`].
//!
//! [`Index`] decodes every function once on all cores and keeps two sorted
//! reference tables, calls and address loads, so each query is a binary
//! search.

pub mod op;
mod thumb;

use std::{
   ops::Range,
   sync::OnceLock,
};

use phoenix_hook::image::Image;

pub use crate::index::op::{
   Isa,
   Native,
   Op,
   Reg,
   Step,
   Value,
};
use crate::{
   Found,
   one,
};

/// How far before a match a string literal can start. Rust merges literals
/// into one blob, so code loads the start of the literal, not the match.
const LITERAL_REACH: usize = 512;

/// The longest `&str` the string table records.
const MAX_STR: usize = 4096;

/// `(target << 32 | site)` as offsets from the image base, sorted.
struct Refs(Vec<u64>);

struct Tables {
   calls: Refs,
   addrs: Refs,
}

/// A `&'static str` stored in data: the slot holding its pointer, and the
/// bytes it points at.
#[derive(Clone, Copy, Debug)]
pub struct StrSlot {
   pub slot: usize,
   pub ptr:  usize,
   pub len:  usize,
}

pub struct Index<'img> {
   pub image: &'img Image<'img>,
   pub isa:   Isa,
   functions: Vec<(usize, usize)>,
   base:      usize,
   tables:    OnceLock<Tables>,
   strs:      OnceLock<Vec<StrSlot>>,
}

impl<'img> Index<'img> {
   #[must_use]
   pub fn new(image: &'img Image<'img>, isa: Isa) -> Self {
      let base = image
         .segments
         .iter()
         .map(|segment| segment.addr)
         .min()
         .unwrap_or(0);
      let mut index = Self {
         image,
         isa,
         functions: image.functions(),
         base,
         tables: OnceLock::new(),
         strs: OnceLock::new(),
      };
      index.add_leaves();
      index
   }

   /// Win64 leaf functions need no unwind data, so `.pdata` leaves them out.
   /// A call target outside every listed function starts one, which ends at
   /// the next listed start.
   fn add_leaves(&mut self) {
      let mut tables = self.build_tables(&self.functions);
      let mut leaves = tables
         .calls
         .0
         .iter()
         .map(|&r| self.base + (r >> 32) as usize)
         .filter(|&target| self.function(target).is_none() && self.image.is_code(target))
         .collect::<Vec<usize>>();
      leaves.sort_unstable();
      leaves.dedup();
      let mut added = Vec::with_capacity(leaves.len());
      for (at, &start) in leaves.iter().enumerate() {
         let next_listed = self.functions[self
            .functions
            .partition_point(|&(listed, _)| listed <= start)..]
            .first()
            .map_or(usize::MAX, |&(listed, _)| listed);
         let next_leaf = leaves.get(at + 1).copied().unwrap_or(usize::MAX);
         let segment_end = self
            .image
            .segments
            .iter()
            .find(|segment| segment.executable && segment.contains(start))
            .map_or(start, |segment| segment.addr + segment.bytes.len());
         let end = next_listed.min(next_leaf).min(segment_end);
         if end > start {
            added.push((start, end));
         }
      }
      let more = self.build_tables(&added);
      for (into, from) in [
         (&mut tables.calls, more.calls),
         (&mut tables.addrs, more.addrs),
      ] {
         into.0.extend(from.0);
         into.0.sort_unstable();
      }
      self.functions.extend(added);
      self.functions.sort_unstable();
      drop(self.tables.set(tables));
   }

   #[must_use]
   pub const fn function_count(&self) -> usize {
      self.functions.len()
   }

   /// The function holding `addr`.
   #[must_use]
   pub fn function(&self, addr: usize) -> Option<Func<'_>> {
      let index = self
         .functions
         .partition_point(|&(start, _)| start <= addr)
         .checked_sub(1)?;
      let (start, end) = self.functions[index];
      (addr < end).then_some(Func {
         ix: self,
         start,
         end,
      })
   }

   /// The function starting at `start`.
   pub fn func(&self, start: usize) -> Found<Func<'_>> {
      self
         .function(start)
         .filter(|func| func.start == start)
         .ok_or_else(|| format!("{start:#x} starts no function"))
   }

   fn funcs(&self, sites: impl IntoIterator<Item = usize>) -> Funcs<'_> {
      let mut list = sites
         .into_iter()
         .filter_map(|site| self.function(site))
         .collect::<Vec<Func<'_>>>();
      list.sort_unstable_by_key(|func| func.start);
      list.dedup_by_key(|func| func.start);
      Funcs { list }
   }

   fn tables(&self) -> &Tables {
      self
         .tables
         .get_or_init(|| self.build_tables(&self.functions))
   }

   fn build_tables(&self, functions: &[(usize, usize)]) -> Tables {
      let pack = |site: usize, target: usize| -> Option<u64> {
         let site = u32::try_from(site.checked_sub(self.base)?).ok()?;
         let target = u32::try_from(target.checked_sub(self.base)?).ok()?;
         Some(u64::from(target) << 32 | u64::from(site))
      };
      let (mut calls, mut addrs) = (Vec::new(), Vec::new());
      for (part_calls, part_addrs) in across(functions, |part| {
         let (mut calls, mut addrs) = (Vec::new(), Vec::new());
         for &(start, end) in part {
            for step in op::decode(self.image, self.isa, start, end) {
               match step.op {
                  Op::Call(target) => calls.extend(pack(step.at, target)),
                  Op::Jump(target) if !(start..end).contains(&target) => {
                     calls.extend(pack(step.at, target));
                  },
                  Op::Addr { target, .. } | Op::Global { target, .. } => {
                     addrs.extend(pack(step.at, target));
                  },
                  _ => {},
               }
            }
         }
         (calls, addrs)
      }) {
         calls.extend(part_calls);
         addrs.extend(part_addrs);
      }
      calls.sort_unstable();
      addrs.sort_unstable();
      Tables {
         calls: Refs(calls),
         addrs: Refs(addrs),
      }
   }

   /// How many calls and address loads the tables hold.
   pub fn ref_counts(&self) -> (usize, usize) {
      let tables = self.tables();
      (tables.calls.0.len(), tables.addrs.0.len())
   }

   /// Builds the reference tables now, which every query below needs.
   pub fn warm(&self) {
      self.tables();
      self.strs();
   }

   /// `(site, target)` for every reference in `refs` landing in `targets`.
   fn range(&self, refs: &Refs, targets: Range<usize>) -> impl Iterator<Item = (usize, usize)> {
      let rva = |addr: usize| {
         u64::try_from(addr.saturating_sub(self.base))
            .unwrap_or(u64::MAX)
            .min(u64::from(u32::MAX) + 1)
      };
      let (low, high) = (rva(targets.start), rva(targets.end));
      let start = refs.0.partition_point(|&r| r >> 32 < low);
      let end = refs.0.partition_point(|&r| r >> 32 < high);
      refs.0[start..end].iter().map(|&r| {
         (
            self.base + (r & 0xFFFF_FFFF) as usize,
            self.base + (r >> 32) as usize,
         )
      })
   }

   /// The functions that load an address in `targets`.
   #[must_use]
   pub fn loaders(&self, targets: Range<usize>) -> Funcs<'_> {
      self.funcs(
         self
            .range(&self.tables().addrs, targets)
            .map(|(site, _)| site),
      )
   }

   /// The sites that load an address in `targets`, with the address.
   pub fn loads_of(&self, targets: Range<usize>) -> Vec<(usize, usize)> {
      self.range(&self.tables().addrs, targets).collect()
   }

   /// The call sites of `callee`.
   pub fn call_sites(&self, callee: usize) -> Vec<usize> {
      self
         .range(&self.tables().calls, callee..callee + 1)
         .map(|(site, _)| site)
         .collect()
   }

   /// The functions whose first `steps` instructions pass `keep`, checked on
   /// all cores.
   #[must_use]
   pub fn heads(&self, steps: usize, keep: impl Fn(&[Step]) -> bool + Sync) -> Funcs<'_> {
      let bytes = steps
         * match self.isa {
            Isa::Aarch64 | Isa::Thumb2 => 4,
            #[cfg(any(target_arch = "x86_64", target_os = "macos"))]
            Isa::X86_64 { .. } => 15,
         };
      let starts = across(&self.functions, |part| {
         part
            .iter()
            .filter(|&&(start, end)| {
               let head = op::decode(self.image, self.isa, start, end.min(start + bytes));
               keep(&head[..head.len().min(steps)])
            })
            .map(|&(start, _)| start)
            .collect::<Vec<_>>()
      })
      .into_iter()
      .flatten()
      .collect::<Vec<usize>>();
      self.funcs(starts)
   }

   /// Where `needle` sits in any segment.
   #[must_use]
   pub fn text(&self, needle: &[u8]) -> Vec<usize> {
      self.image.find_bytes(needle)
   }

   /// The functions that load the string literal holding `needle`. Each hit
   /// counts the loads of the closest literal start at or before it.
   #[must_use]
   pub fn literal(&self, needle: &[u8]) -> Funcs<'_> {
      let mut sites = Vec::new();
      for hit in self.text(needle) {
         let loads = self.loads_of(hit.saturating_sub(LITERAL_REACH)..hit + 1);
         let Some(closest) = loads.iter().map(|&(_, target)| target).max() else {
            continue;
         };
         sites.extend(
            loads
               .iter()
               .filter(|&&(_, target)| target == closest)
               .map(|&(site, _)| site),
         );
      }
      self.funcs(sites)
   }

   /// Every `(ptr, len)` pair in data that points at UTF-8 bytes in the image,
   /// sorted by `ptr`.
   pub fn strs(&self) -> &[StrSlot] {
      self.strs.get_or_init(|| {
         let width = self.image.pointer_width;
         // A 64-bit image read on a 32-bit host has no pointers it could use.
         let word = |bytes: &[u8]| -> usize {
            let mut raw = [0u8; 8];
            raw[..width].copy_from_slice(&bytes[..width]);
            usize::try_from(u64::from_le_bytes(raw)).unwrap_or(usize::MAX)
         };
         let mut found = Vec::new();
         for segment in self
            .image
            .segments
            .iter()
            .filter(|segment| !segment.executable)
         {
            let words = segment.bytes.len() / width;
            for index in 0..words.saturating_sub(1) {
               let at = index * width;
               let len = word(&segment.bytes[at + width..]);
               if !(1..=MAX_STR).contains(&len) {
                  continue;
               }
               let ptr = word(&segment.bytes[at..]);
               if let Some(bytes) = self.image.read(ptr, len)
                  && std::str::from_utf8(bytes).is_ok()
               {
                  found.push(StrSlot {
                     slot: segment.addr + at,
                     ptr,
                     len,
                  });
               }
            }
         }
         found.sort_unstable_by_key(|slot| (slot.ptr, slot.slot));
         found
      })
   }

   /// The stored `&str`s whose bytes hold `addr`.
   pub fn strs_over(&self, addr: usize) -> impl Iterator<Item = StrSlot> + '_ {
      let strs = self.strs();
      let end = strs.partition_point(|slot| slot.ptr <= addr);
      let start = strs.partition_point(|slot| slot.ptr + MAX_STR <= addr);
      strs[start..end]
         .iter()
         .copied()
         .filter(move |slot| addr < slot.ptr + slot.len)
   }

   /// The bytes of a stored `&str`.
   #[must_use]
   pub fn str_of(&self, slot: StrSlot) -> &str {
      self
         .image
         .read(slot.ptr, slot.len)
         .and_then(|bytes| std::str::from_utf8(bytes).ok())
         .unwrap_or_default()
   }

   /// Every panic [`Location`] in the image.
   pub fn locations(&self) -> impl Iterator<Item = Location> + '_ {
      let width = self.image.pointer_width;
      self.strs().iter().filter_map(move |&file| {
         let bytes = self.image.read(file.ptr, file.len)?;
         if !bytes.ends_with(b".rs") {
            return None;
         }
         let line = self.image.read_u32(file.slot + 2 * width)?;
         let column = self.image.read_u32(file.slot + 2 * width + 4)?;
         ((1..1_000_000).contains(&line) && (1..1_000).contains(&column)).then_some(Location {
            file,
            line,
            column,
         })
      })
   }

   /// The [`Location`] stored at `addr`, if one is.
   #[must_use]
   pub fn location_at(&self, addr: usize) -> Option<Location> {
      let width = self.image.pointer_width;
      let file = StrSlot {
         slot: addr,
         ptr:  self.image.read_usize(addr)?,
         len:  self.image.read_usize(addr + width)?,
      };
      if file.len > MAX_STR || !self.image.read(file.ptr, file.len)?.ends_with(b".rs") {
         return None;
      }
      let line = self.image.read_u32(addr + 2 * width)?;
      let column = self.image.read_u32(addr + 2 * width + 4)?;
      ((1..1_000_000).contains(&line) && (1..1_000).contains(&column)).then_some(Location {
         file,
         line,
         column,
      })
   }

   /// The functions that can panic at a [`Location`] in a file whose path
   /// ends in `suffix`, `/` matching either separator.
   #[must_use]
   pub fn source(&self, suffix: &str) -> Funcs<'_> {
      let sites = self
         .locations()
         .filter(|location| location.ends_with(self, suffix))
         .flat_map(|location| {
            self
               .loads_of(location.file.slot..location.file.slot + 1)
               .into_iter()
               .map(|(site, _)| site)
         })
         .collect::<Vec<usize>>();
      self.funcs(sites)
   }

   /// The functions that enter a tracing span or event whose target is
   /// `target`, like `libdiscord_media::fetch`, through the callsite its
   /// metadata names.
   #[must_use]
   pub fn tracing(&self, target: &str) -> Funcs<'_> {
      let width = self.image.pointer_width;
      let mut sites = Vec::new();
      for hit in self.text(target.as_bytes()) {
         for slot in self.strs_over(hit) {
            if slot.ptr != hit || slot.len != target.len() {
               continue;
            }
            // The metadata's field set names its callsite static, and the
            // callsite points back at the metadata, which opens a few words
            // before `name: &str`. Code loads the callsite.
            let name = slot.slot.saturating_sub(2 * width);
            let opens = name.saturating_sub(6 * width)..name + 1;
            let back = |callsite: usize| {
               (0..6).any(|word| {
                  self
                     .image
                     .read_usize(callsite + word * width)
                     .is_some_and(|meta| opens.contains(&meta))
               })
            };
            for word in (name..name + 14 * width).step_by(width) {
               let Some(callsite) = self.image.read_usize(word).filter(|&at| back(at)) else {
                  continue;
               };
               sites.extend(
                  self
                     .loads_of(callsite..callsite + 1)
                     .into_iter()
                     .map(|(site, _)| site),
               );
            }
         }
      }
      self.funcs(sites)
   }
}

/// `work` over `functions` split across the cores, in order. Targets with one
/// thread, wasm among them, run it inline.
#[expect(
   clippy::needless_collect,
   reason = "every chunk spawns before the first join"
)]
fn across<T: Send>(
   functions: &[(usize, usize)],
   work: impl Fn(&[(usize, usize)]) -> T + Sync,
) -> Vec<T> {
   let threads = std::thread::available_parallelism().map_or(1, usize::from);
   if threads <= 1 {
      return vec![work(functions)];
   }
   let chunk = functions.len().div_ceil(threads).max(1);
   let work = &work;
   std::thread::scope(|scope| {
      let handles = functions
         .chunks(chunk)
         .map(|part| scope.spawn(move || work(part)))
         .collect::<Vec<_>>();
      handles
         .into_iter()
         .map(|handle| {
            handle
               .join()
               .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
         })
         .collect()
   })
}

/// A `core::panic::Location`, `{ file: &str, line: u32, col: u32 }`.
#[derive(Clone, Copy, Debug)]
pub struct Location {
   pub file:   StrSlot,
   pub line:   u32,
   pub column: u32,
}

impl Location {
   fn ends_with(&self, ix: &Index<'_>, suffix: &str) -> bool {
      let file = ix.str_of(self.file).as_bytes();
      file.len() >= suffix.len()
         && file[file.len() - suffix.len()..]
            .iter()
            .zip(suffix.as_bytes())
            .all(|(&have, &want)| have == want || (want == b'/' && have == b'\\'))
   }
}

/// A function the unwind table bounds.
#[derive(Clone, Copy)]
pub struct Func<'ix> {
   ix:        &'ix Index<'ix>,
   pub start: usize,
   pub end:   usize,
}

impl std::fmt::Debug for Func<'_> {
   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      write!(f, "{:#x}", self.start)
   }
}

impl<'ix> Func<'ix> {
   #[must_use]
   pub const fn size(&self) -> usize {
      self.end - self.start
   }

   #[must_use]
   pub fn steps(&self) -> Vec<Step> {
      op::decode(self.ix.image, self.ix.isa, self.start, self.end)
   }

   /// The functions this one calls, in instruction order, tail jumps
   /// included. On arm64 the outliner turns repeated sequences into a few
   /// frameless instructions ending in `b T` or `ret`: a call to one counts as
   /// a call to `T`, or as none.
   #[must_use]
   pub fn calls(&self) -> Vec<usize> {
      self
         .calls_at()
         .into_iter()
         .map(|(_, callee)| callee)
         .collect()
   }

   /// [`Func::calls`] with the address of each call site.
   #[must_use]
   pub fn calls_at(&self) -> Vec<(usize, usize)> {
      self
         .steps()
         .iter()
         .filter_map(|step| {
            let callee = match step.op {
               Op::Call(target) => self.through_outlined(target),
               Op::Jump(target) if !(self.start..self.end).contains(&target) => Some(target),
               _ => None,
            }?;
            Some((step.at, callee))
         })
         .collect()
   }

   fn through_outlined(&self, target: usize) -> Option<usize> {
      const MOST: usize = 6;
      if self.ix.isa != Isa::Aarch64 {
         return Some(target);
      }
      let Some(callee) = self.ix.function(target) else {
         return Some(target);
      };
      if callee.size() > MOST * 4 {
         return Some(target);
      }
      for step in op::decode(self.ix.image, self.ix.isa, target, callee.end) {
         match step.op {
            Op::Jump(tail) => return Some(tail),
            Op::Ret => return None,
            Op::Call(_) | Op::Branch(_) => return Some(target),
            _ => {},
         }
      }
      Some(target)
   }

   /// The addresses this function loads, in instruction order.
   #[must_use]
   pub fn loads(&self) -> Vec<usize> {
      self
         .steps()
         .iter()
         .filter_map(|step| {
            match step.op {
               Op::Addr { target, .. } | Op::Global { target, .. } => Some(target),
               _ => None,
            }
         })
         .collect()
   }

   #[must_use]
   pub fn callers(&self) -> Funcs<'ix> {
      self.ix.funcs(self.ix.call_sites(self.start))
   }

   /// The function after this one in the image.
   #[must_use]
   pub fn next(&self) -> Option<Self> {
      let at = self
         .ix
         .functions
         .partition_point(|&(start, _)| start < self.end);
      let &(start, end) = self.ix.functions.get(at)?;
      Some(Self {
         ix: self.ix,
         start,
         end,
      })
   }

   /// The `n`th function this one calls.
   pub fn call(&self, n: usize) -> Found<Self> {
      let callee = *self
         .calls()
         .get(n)
         .ok_or_else(|| format!("{self:?} makes no call {n}"))?;
      self.ix.func(callee)
   }
}

/// A set of functions, sorted by start, each once.
pub struct Funcs<'ix> {
   list: Vec<Func<'ix>>,
}

impl<'ix> Funcs<'ix> {
   #[must_use]
   pub fn filter(self, keep: impl Fn(&Func<'ix>) -> bool) -> Self {
      Self {
         list: self.list.into_iter().filter(|func| keep(func)).collect(),
      }
   }

   /// The only function, or how many there were.
   pub fn one(&self, what: &str) -> Found<Func<'ix>> {
      one(what, &self.list)
   }

   /// Every function that calls one of these.
   #[must_use]
   pub fn callers(&self) -> Self {
      let Some(first) = self.list.first() else {
         return Self { list: Vec::new() };
      };
      first.ix.funcs(
         self
            .list
            .iter()
            .flat_map(|func| first.ix.call_sites(func.start)),
      )
   }

   /// These functions that also appear in `other`.
   #[must_use]
   pub fn and(self, other: &Self) -> Self {
      self.filter(|func| other.list.iter().any(|them| them.start == func.start))
   }

   #[must_use]
   pub const fn len(&self) -> usize {
      self.list.len()
   }

   #[must_use]
   pub const fn is_empty(&self) -> bool {
      self.list.is_empty()
   }

   pub fn iter(&self) -> impl Iterator<Item = &Func<'ix>> {
      self.list.iter()
   }
}

impl<'ix> IntoIterator for Funcs<'ix> {
   type IntoIter = std::vec::IntoIter<Func<'ix>>;
   type Item = Func<'ix>;

   fn into_iter(self) -> Self::IntoIter {
      self.list.into_iter()
   }
}
