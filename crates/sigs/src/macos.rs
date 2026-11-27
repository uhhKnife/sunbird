//! Locators for macOS Phoenix, the arm64 desktop client.

use std::collections::{
   BTreeMap,
   HashMap,
};

use phoenix_hook::{
   arm64::{
      self,
      Insn,
      decode_at,
   },
   image::Image,
   pattern::Pattern,
};

use crate::{
   Found,
   desktop::{
      ButtonLayout,
      DivLayout,
      Gpui,
      GpuiLayout,
      MenuLayout,
      SwitchLayout,
      layout,
   },
   http::{
      DesktopHttpTransport,
      RequestLayout,
      ResponseLayout,
      find_vtable_method_slots,
   },
   one,
};

/// `Some(out)` for the first arm `value` matches, else `None`, or without
/// `in value` a closure doing that to its argument.
macro_rules! pick {
   (in $value:expr, $($pat:pat $(if $guard:expr)? => $out:expr),+ $(,)?) => {
      match $value {
         $($pat $(if $guard)? => Some($out),)+
         _ => None,
      }
   };
   ($($arms:tt)+) => {
      |value| pick!(in value, $($arms)+)
   };
}

/// The shell script Discord's updater runs to start Discord again once it has
/// quit: it waits for the old pid, opens the app bundle and removes the old
/// build.
pub const RELAUNCH_SCRIPT: &[u8] =
   br#"while kill -0 "$0" 2>/dev/null; do sleep 0.2; done; /usr/bin/open -n "$1"; rm -rf "$2""#;

pub fn relaunch_script(image: &Image<'_>) -> Found<usize> {
   one("relaunch script", &image.find_bytes(RELAUNCH_SCRIPT))
}

/// Up to `count` instructions at `at`, none if they can't all be read.
fn decoded(image: &Image<'_>, at: usize, count: usize) -> Vec<Insn> {
   let code = image.read(at, count * 4).unwrap_or_default();
   arm64::decode_all(code, at).map(|(_, insn)| insn).collect()
}

fn words(code: &[u8]) -> impl Iterator<Item = u32> {
   code
      .as_chunks::<4>()
      .0
      .iter()
      .map(|&word| u32::from_le_bytes(word))
}

fn code_words(image: &Image<'_>) -> impl Iterator<Item = (usize, u32)> {
   let segments = image.segments.iter().filter(|segment| segment.executable);
   segments.flat_map(|segment| {
      words(&segment.bytes)
         .enumerate()
         .map(|(index, word)| (segment.addr + index * 4, word))
   })
}

fn sorted<T: Ord>(mut values: Vec<T>) -> Vec<T> {
   values.sort_unstable();
   values.dedup();
   values
}

fn refs_to(image: &Image<'_>, anchors: &[usize]) -> Vec<(usize, usize)> {
   let mut ranges = anchors.iter().map(|&at| at..at + 1).collect::<Vec<_>>();
   ranges.sort_unstable_by_key(|range| range.start);
   arm64::code_refs(image, &ranges)
}

/// The functions that load or call any of `anchors`, each once, in address
/// order.
fn loaders(image: &Image<'_>, anchors: &[usize]) -> Vec<usize> {
   let sites = refs_to(image, anchors).into_iter();
   sorted(
      sites
         .filter_map(|(site, _)| image.function_containing(site))
         .collect(),
   )
}

/// `mov w0, #2; ret`: the access function's "no gate".
pub const NO_GATE: [u8; 8] = [0x40, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6];

/// `mov w0, #0; ret`: `enforced` answering false.
pub const NOT_ENFORCED: [u8; 8] = [0x00, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6];

/// [`DesktopHttpTransport::locate`] for arm64.
///
/// It finds `send` by the anchor string it loads, its `dyn Transport` slots by
/// value, and the `SendFuture` vtable by the `adrp` pair that loads it in
/// `send` or a small callee that boxes the future. The host allocator is not
/// located, so response bodies keep Discord's own buffers.
pub fn http_transport(image: &Image<'_>) -> Found<DesktopHttpTransport> {
   let anchors = image.find_bytes(crate::http::HOST_FILE_ANCHOR);
   let anchor = one("transport anchor", &anchors)?;
   let sites = refs_to(image, &[anchor])
      .into_iter()
      .filter_map(|(site, _)| image.function_containing(site))
      .collect::<Vec<_>>();
   let send_fn = one("transport anchor load", &sites)?;
   let send_slots = find_vtable_method_slots(image, send_fn, 1..=0x2000);
   if send_slots.is_empty() {
      return Err("no Transport vtable holds ReqwestTransport::send".to_owned());
   }
   let (_, body) = arm64::function(image, send_fn).ok_or("send has no bounds")?;
   let send_bounds = image.function_bounds(send_fn).ok_or("send has no bounds")?;
   let small = |at: usize| {
      image
         .function_bounds(at)
         .filter(|&(start, end)| start == at && end - start <= 0x80)
   };
   let boxers = body
      .iter()
      .filter_map(pick!(&(_, Insn::Bl { target }) => small(target)?))
      .collect::<Vec<_>>();
   let mut found = future_vtables(image, &boxers);
   if found.is_empty() {
      found = future_vtables(image, &[send_bounds]);
   }
   let [(vtable, poll_fn)] = found[..] else {
      return Err(format!("{} SendFuture vtable candidates", found.len()));
   };
   let mut poll_slots = find_vtable_method_slots(image, poll_fn, 0x100..=0x4000);
   if !poll_slots.contains(&(vtable + 24)) {
      poll_slots.push(vtable + 24);
   }
   Ok(DesktopHttpTransport {
      send_slots,
      send_fn,
      request: request_layout(image, send_fn)?,
      poll_slots,
      poll_fn,
      response: poll_response_layout(image, poll_fn),
      host_alloc: None,
      host_dealloc: None,
   })
}

/// Decodes `send`'s request layout (`body`, `url`, `method`) on arm64 by
/// following `x1` through `Client::request`, the `HeaderMap` copy, and the body
/// tag jump table.
fn request_layout(image: &Image<'_>, send_fn: usize) -> Found<RequestLayout> {
   request_layout_in(&flattened(image, send_fn))
}

#[expect(
   clippy::too_many_lines,
   reason = "tracks request registers, stack copies and jump-table dispatch in one pass"
)]
fn request_layout_in(code: &[Insn]) -> Found<RequestLayout> {
   use crate::http::{
      BODY_SIZE,
      HEADER_MAP_SIZE,
      STRING_SIZE,
   };

   #[derive(Clone, Copy)]
   enum Val {
      Req(usize),
      Stack(usize),
      Field(usize),
      Table(usize),
      Imm(usize),
   }

   let mut regs = [None::<Val>; 32];
   let mut qregs = [None::<usize>; 32];
   let mut stack_copies = HashMap::<usize, usize>::new();
   regs[1] = Some(Val::Req(0));

   let resolve_arg = |val: Option<Val>, copies: &HashMap<usize, usize>| {
      match val {
         Some(Val::Req(off)) => Some(off),
         Some(Val::Stack(slot)) => copies.get(&slot).copied(),
         _ => None,
      }
   };

   let mut prev_call: Option<(Option<usize>, Option<usize>)> = None;
   let mut method_url: Option<(Option<usize>, Option<usize>)> = None;
   let mut dispatches = Vec::new();

   for &insn in code {
      if let Some((load, rt, rn, off)) = simd_q(insn) {
         if load {
            qregs[usize::from(rt)] = match regs[usize::from(rn)] {
               Some(Val::Req(base)) => base.checked_add_signed(off),
               _ => None,
            };
         } else if let Some(field) = qregs[usize::from(rt)] {
            let slot = if rn == 31 {
               usize::try_from(off).ok()
            } else if let Some(Val::Stack(base)) = regs[usize::from(rn)] {
               base.checked_add_signed(off)
            } else {
               None
            };
            if let Some(slot) = slot {
               stack_copies.insert(slot, field);
            }
         }
         continue;
      }
      if let Some((load, rt, rt2, rn, off)) = pair(insn) {
         if load {
            let base = match regs[usize::from(rn)] {
               Some(Val::Req(base)) => Some(base),
               _ => None,
            };
            regs[usize::from(rt)] = base.and_then(|b| b.checked_add_signed(off)).map(Val::Field);
            regs[usize::from(rt2)] = base
               .and_then(|b| b.checked_add_signed(off + 8))
               .map(Val::Field);
         }
         continue;
      }
      if let Some((rt, rn, rm)) = indexed_load(insn) {
         regs[usize::from(rt)] = match (regs[usize::from(rn)], regs[usize::from(rm)]) {
            (_, Some(Val::Field(off))) | (Some(Val::Field(off)), _) => Some(Val::Table(off)),
            _ => None,
         };
         continue;
      }
      if let Some((rd, rn, rm)) = add_reg(insn) {
         regs[usize::from(rd)] = match (regs[usize::from(rn)], regs[usize::from(rm)]) {
            (_, Some(Val::Table(off) | Val::Field(off)))
            | (Some(Val::Table(off) | Val::Field(off)), _) => Some(Val::Table(off)),
            _ => None,
         };
         continue;
      }

      match insn {
         Insn::MovReg { rd, rm, .. } => regs[usize::from(rd)] = regs[usize::from(rm)],
         Insn::MovZ { rd, imm, .. } => {
            regs[usize::from(rd)] = usize::try_from(imm).ok().map(Val::Imm);
         },
         Insn::AddImm { rd, rn, imm } => {
            if rd != 31 {
               regs[usize::from(rd)] = if rn == 31 {
                  Some(Val::Stack(imm))
               } else {
                  match regs[usize::from(rn)] {
                     Some(Val::Req(base)) => Some(Val::Req(base + imm)),
                     Some(Val::Stack(base)) => Some(Val::Stack(base + imm)),
                     _ => None,
                  }
               };
            }
         },
         Insn::Load { rt, rn, offset, .. } => {
            regs[usize::from(rt)] = match regs[usize::from(rn)] {
               Some(Val::Req(base)) => Some(Val::Field(base + offset)),
               _ => None,
            };
         },
         Insn::Writeback {
            rt,
            rn,
            imm,
            load: true,
         } => {
            let next = match regs[usize::from(rn)] {
               Some(Val::Req(base)) => base.checked_add_signed(imm),
               _ => None,
            };
            regs[usize::from(rn)] = next.map(Val::Req);
            regs[usize::from(rt)] = next.map(Val::Field);
         },
         Insn::Store { rt, rn, offset, .. } => {
            if let Some(Val::Field(field)) = regs[usize::from(rt)] {
               let slot = if rn == 31 {
                  Some(offset)
               } else if let Some(Val::Stack(base)) = regs[usize::from(rn)] {
                  Some(base + offset)
               } else {
                  None
               };
               if let Some(slot) = slot {
                  stack_copies.insert(slot, field);
               }
            }
         },
         Insn::Br { rn } => {
            if let Some(Val::Table(off)) = regs[usize::from(rn)] {
               dispatches.push(off);
            }
         },
         Insn::Bl { .. } => {
            if method_url.is_none()
               && matches!(regs[1], Some(Val::Req(0)))
               && matches!(regs[2], Some(Val::Imm(HEADER_MAP_SIZE)))
            {
               method_url = prev_call;
            }
            prev_call = Some((
               resolve_arg(regs[1], &stack_copies),
               resolve_arg(regs[2], &stack_copies),
            ));
            for slot in &mut regs[..=18] {
               *slot = None;
            }
            qregs = [None; 32];
         },
         Insn::Adrp { rd, .. } | Insn::MovN { rd, .. } | Insn::Cset { rd, .. } => {
            regs[usize::from(rd)] = None;
         },
         _ => {},
      }
   }

   let Some((Some(method), Some(url))) = method_url else {
      return Err(format!(
         "the request call takes {method_url:x?}, not a method and URL"
      ));
   };
   let dispatches = sorted(dispatches);
   let [body] = dispatches[..] else {
      return Err(format!("{dispatches:#x?} could each be the body's tag"));
   };
   let mut fields = [
      (0, HEADER_MAP_SIZE),
      (body, BODY_SIZE),
      (url, STRING_SIZE),
      (method, STRING_SIZE),
   ];
   fields.sort_unstable();
   if fields
      .windows(2)
      .any(|pair| pair[0].0 + pair[0].1 > pair[1].0)
      || fields.iter().any(|&(offset, _)| offset % 8 != 0)
   {
      return Err(format!(
         "body {body:#x}, url {url:#x} and method {method:#x} overlap"
      ));
   }
   Ok(RequestLayout { body, url, method })
}

/// Measures `SendFuture::poll`'s return size and decodes its `ResponseLayout`.
fn poll_response_layout(image: &Image<'_>, poll_fn: usize) -> Found<ResponseLayout> {
   let code = flattened(image, poll_fn);
   let size = poll_result_size_in(&code);
   if size <= crate::http::BUFFERED_RESULT_SIZE {
      return Ok(ResponseLayout::Buffered);
   }
   stream_response_layout_in(&code, size, |vtable| is_stream_vtable(image, vtable))
      .ok_or_else(|| format!("poll writes {size:#x} bytes of its result"))
}

fn is_stream_vtable(image: &Image<'_>, vtable: usize) -> bool {
   let read = |at: usize| image.read_usize(vtable + at);
   let (Some(drop_fn), Some(size), Some(align), Some(poll_next), Some(size_hint)) =
      (read(0), read(8), read(16), read(24), read(32))
   else {
      return false;
   };
   image.is_function(drop_fn)
      && image.is_function(poll_next)
      && image.is_function(size_hint)
      && (1..=0x1000).contains(&size)
      && align.is_power_of_two()
      && align <= 64
}

fn stream_response_layout_in(
   code: &[Insn],
   size: usize,
   valid_vtable: impl Fn(usize) -> bool,
) -> Option<ResponseLayout> {
   let mut regs: Regs = [None; 32];
   regs[8] = Some(Held::SelfAt(0));

   let mut body = None::<usize>;
   let mut status = None::<usize>;
   let mut err_tag = None::<u64>;
   let mut pending_tag = None::<u64>;
   let mut stream_tag_off = None::<usize>;

   for &insn in code {
      if let Some((false, rt, _, rn, off)) = pair(insn)
         && let Some(Held::SelfAt(base)) = regs[usize::from(rn)]
         && let Some(at) = base.checked_add_signed(off)
         && let Some(Held::Imm(tag)) = regs[usize::from(rt)]
      {
         if at == 0 && tag < 16 {
            err_tag = Some(tag);
         } else if tag == 1 {
            stream_tag_off = Some(at);
         }
      } else if let Insn::Store {
         rt,
         rn,
         offset,
         size: store_size,
      } = insn
         && let Some(Held::SelfAt(base)) = regs[usize::from(rn)]
      {
         let at = base + offset;
         if store_size == 8
            && at == 0
            && let Some(Held::Imm(tag)) = regs[usize::from(rt)]
         {
            if tag == u64::MAX {
               pending_tag = Some(tag);
            } else if tag < 16 {
               err_tag = Some(tag);
            }
         } else if store_size == 8
            && let Some(Held::Addr(vtable) | Held::Page(vtable)) = regs[usize::from(rt)]
            && let Some(tag_off) = stream_tag_off
            && at == tag_off + 0x10
            && valid_vtable(vtable)
         {
            body = Some(tag_off);
         } else if store_size == 2
            && let Some(body_off) = body
            && at >= body_off + 0x28
            && status.is_none()
         {
            status = Some(at);
         }
      }
      step(&mut regs, insn);
   }

   let (Some(body), Some(status), Some(err_tag), Some(pending_tag)) =
      (body, status, err_tag, pending_tag)
   else {
      return None;
   };
   if body != crate::http::STREAMED_BODY
      || size > crate::http::STREAMED_RESULT_SIZE
      || err_tag != 2
      || pending_tag != u64::MAX
      || status + 2 > size
      || !status.is_multiple_of(2)
   {
      return None;
   }
   Some(ResponseLayout::Streamed { status })
}

fn poll_result_size_in(code: &[Insn]) -> usize {
   let mut regs: Regs = [None; 32];
   regs[8] = Some(Held::SelfAt(0));
   let mut max = 0usize;

   for &insn in code {
      if let Some((false, _, rn, off)) = simd_q(insn) {
         if let Some(Held::SelfAt(base)) = regs[usize::from(rn)]
            && let Some(end) = base.checked_add_signed(off + 16)
         {
            max = max.max(end);
         }
      } else if let Some((rn, off)) = simd_q_pair_store(insn) {
         if let Some(Held::SelfAt(base)) = regs[usize::from(rn)]
            && let Some(end) = base.checked_add_signed(off + 32)
         {
            max = max.max(end);
         }
      } else if let Some((false, _, _, rn, off)) = pair(insn) {
         if let Some(Held::SelfAt(base)) = regs[usize::from(rn)]
            && let Some(end) = base.checked_add_signed(off + 16)
         {
            max = max.max(end);
         }
      } else if let Insn::Store {
         rn, offset, size, ..
      } = insn
      {
         if let Some(Held::SelfAt(base)) = regs[usize::from(rn)] {
            max = max.max(base + offset + size);
         }
      } else if let Insn::Bl { .. } = insn
         && let (Some(Held::SelfAt(base)), Some(Held::Imm(len))) = (regs[0], regs[2])
         && let Ok(len) = usize::try_from(len)
      {
         max = max.max(base + len);
      }
      step(&mut regs, insn);
   }
   (max + 7) & !7
}

const fn simd_q(insn: Insn) -> Option<(bool, u8, u8, isize)> {
   let Insn::Other(word) = insn else {
      return None;
   };
   let rt = (word & 31) as u8;
   let rn = ((word >> 5) & 31) as u8;
   match word {
      _ if word & 0xFFC0_0000 == 0x3D80_0000 => {
         Some((
            false,
            rt,
            rn,
            (((word >> 10) & 0xFFF).cast_signed() as isize) * 16,
         ))
      },
      _ if word & 0xFFC0_0000 == 0x3DC0_0000 => {
         Some((
            true,
            rt,
            rn,
            (((word >> 10) & 0xFFF).cast_signed() as isize) * 16,
         ))
      },
      _ if word & 0xFFE0_0C00 == 0x3C80_0000 => {
         let imm = (((word >> 12) & 0x1FF) << 23).cast_signed() >> 23;
         Some((false, rt, rn, imm as isize))
      },
      _ if word & 0xFFE0_0C00 == 0x3CC0_0000 => {
         let imm = (((word >> 12) & 0x1FF) << 23).cast_signed() >> 23;
         Some((true, rt, rn, imm as isize))
      },
      _ => None,
   }
}

const fn simd_q_pair_store(insn: Insn) -> Option<(u8, isize)> {
   let Insn::Other(word) = insn else {
      return None;
   };
   if word & 0xFFC0_0000 != 0xAD00_0000 {
      return None;
   }
   let rn = ((word >> 5) & 31) as u8;
   let imm = (((word >> 15) & 0x7F) << 25).cast_signed() >> 25;
   Some((rn, imm as isize * 16))
}

const fn indexed_load(insn: Insn) -> Option<(u8, u8, u8)> {
   let Insn::Other(word) = insn else {
      return None;
   };
   if word & 0x3F20_0C00 != 0x3820_0800 || word & 0x00C0_0000 == 0 {
      return None;
   }
   Some((
      (word & 31) as u8,
      ((word >> 5) & 31) as u8,
      ((word >> 16) & 31) as u8,
   ))
}

const fn add_reg(insn: Insn) -> Option<(u8, u8, u8)> {
   let Insn::Other(word) = insn else {
      return None;
   };
   if word & 0x7F20_0000 != 0x0B00_0000 && word & 0x7FE0_0000 != 0x0B20_0000 {
      return None;
   }
   Some((
      (word & 31) as u8,
      ((word >> 5) & 31) as u8,
      ((word >> 16) & 31) as u8,
   ))
}

/// Host `(__rust_alloc, __rust_dealloc)` from `alloc_or_oom`: its first call
/// reaches `__rust_alloc`, and `__rust_dealloc` sits right after it (negating
/// the size for its live-bytes counter with an atomic `ldadd`).
pub fn host_allocator(image: &Image<'_>, alloc_or_oom: usize) -> Found<(usize, usize)> {
   let alloc = flattened_at(image, alloc_or_oom)
      .into_iter()
      .find_map(pick!((_, Insn::Bl { target }) if image.is_function(target) => target))
      .ok_or("alloc_or_oom calls no allocator")?;
   let (_, end) = image
      .function_bounds(alloc)
      .ok_or("__rust_alloc has no bounds")?;
   let (dealloc, dealloc_end) = image
      .function_bounds(end)
      .ok_or("nothing follows __rust_alloc")?;
   let code = image
      .read(dealloc, dealloc_end - dealloc)
      .ok_or("__rust_dealloc is unmapped")?;
   let negates = words(code).any(|word| word & 0xFFE0_FFE0 == 0xCB00_03E0);
   let counts = words(code).any(|word| word & 0xFF20_FC00 == 0xF820_0000);
   if dealloc != end || !negates || !counts {
      return Err(format!(
         "no __rust_dealloc after __rust_alloc {alloc:#x} (next {dealloc:#x})"
      ));
   }
   Ok((alloc, dealloc))
}

/// `(vtable, poll_fn)` for each address one of `bounds` builds that reads as a
/// boxed future's vtable: `[drop, size, align 8, poll]`.
fn future_vtables(image: &Image<'_>, bounds: &[(usize, usize)]) -> Vec<(usize, usize)> {
   let mut found = Vec::new();
   for &(start, end) in bounds {
      let code = image.read(start, end - start).unwrap_or_default();
      for (_, vtable) in loaded(&arm64::decode_all(code, start).collect::<Vec<_>>())
         .into_iter()
         .flatten()
      {
         let read = |at: usize| image.read_usize(vtable + at);
         if let (Some(drop_fn), Some(size), Some(8), Some(poll_fn)) =
            (read(0), read(8), read(16), read(24))
            && image.is_function(drop_fn)
            && image.is_function(poll_fn)
            && (0x100..=0x4000).contains(&size)
         {
            found.push((vtable, poll_fn));
         }
      }
   }
   sorted(found)
}

/// `cmp wN, #0xe`, written over the visibility guard's `cmp wN, #0xf`.
#[must_use]
pub const fn lowered_guard(cmp: u32) -> u32 {
   (cmp & !(0xFFF << 10)) | (0xE << 10)
}

/// What a register holds while a function body is read: an offset into a base
/// pointer (`x0`, `x8`, or `sp`), an `adrp` page, an absolute address, or a
/// constant.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Held {
   SelfAt(usize),
   Page(usize),
   Addr(usize),
   Imm(u64),
}

type Regs = [Option<Held>; 32];

fn step(regs: &mut Regs, insn: Insn) {
   match insn {
      Insn::Adrp { rd, page } if rd != 31 => regs[usize::from(rd)] = Some(Held::Page(page)),
      Insn::AddImm { rd, rn, imm } if rd != 31 => {
         regs[usize::from(rd)] = pick!(in regs[usize::from(rn)],
            Some(Held::SelfAt(at)) => Held::SelfAt(at + imm),
            Some(Held::Page(at) | Held::Addr(at)) => Held::Addr(at + imm),
         );
      },
      Insn::MovReg { rd, rm, wide: true } if rd != 31 => {
         regs[usize::from(rd)] = regs[usize::from(rm)];
      },
      Insn::MovReg {
         rd,
         rm,
         wide: false,
      } if rd != 31 => {
         regs[usize::from(rd)] = match regs[usize::from(rm)] {
            Some(Held::Imm(v)) => Some(Held::Imm(v & u64::from(u32::MAX))),
            _ => None,
         };
      },
      Insn::MovZ { rd, imm, .. } if rd != 31 => regs[usize::from(rd)] = Some(Held::Imm(imm)),
      Insn::MovN { rd, imm, wide } if rd != 31 => {
         regs[usize::from(rd)] = Some(Held::Imm(if wide {
            !imm
         } else {
            !imm & u64::from(u32::MAX)
         }));
      },
      // Calls keep only the callee-saved registers.
      Insn::Bl { .. } | Insn::Blr { .. } => regs[..19].fill(None),
      Insn::Load { rt, .. } | Insn::Cset { rd: rt, .. } if rt != 31 => {
         regs[usize::from(rt)] = None;
      },
      Insn::Writeback { rt, rn, imm, load } => {
         if rn != 31 {
            regs[usize::from(rn)] = match regs[usize::from(rn)] {
               Some(Held::SelfAt(at)) => at.checked_add_signed(imm).map(Held::SelfAt),
               _ => None,
            };
         }
         if load && rt != 31 {
            regs[usize::from(rt)] = None;
         }
      },
      // Anything else that writes an integer register forgets it.
      Insn::Other(word) => {
         if let Some((load, rt, rt2, _, _)) = pair(insn) {
            if load {
               if rt != 31 {
                  regs[usize::from(rt)] = None;
               }
               if rt2 != 31 {
                  regs[usize::from(rt2)] = None;
               }
            }
         } else if simd_q(insn).is_none() && simd_q_pair_store(insn).is_none() {
            let dst = (word & 0x1F) as usize;
            if dst != 31 {
               regs[dst] = None;
            }
         }
      },
      _ => {},
   }
}

/// Every call in `body` with the registers that reach it on every path, from
/// `entry` at the start. Branches are followed, and where paths meet a
/// register keeps a value only when they agree.
fn calls_with_regs(body: &[(usize, Insn)], entry: &Regs) -> Vec<(usize, usize, Regs)> {
   let mut seen: HashMap<usize, Regs> = HashMap::new();
   let mut calls = BTreeMap::new();
   let mut work = vec![(0usize, *entry)];
   // Bounded, since each revisit only forgets registers.
   let mut budget = body.len() * 8;
   while let Some((mut index, mut regs)) = work.pop() {
      loop {
         if budget == 0 {
            return Vec::new();
         }
         budget -= 1;
         let Some(&(pc, insn)) = body.get(index) else {
            break;
         };
         if let Some(known) = seen.get(&index) {
            let merged =
               std::array::from_fn(|at| (known[at] == regs[at]).then_some(known[at]).flatten());
            if merged == *known {
               break;
            }
            regs = merged;
         }
         seen.insert(index, regs);
         if let Insn::Bl { target } = insn {
            calls.insert(pc, (target, regs));
         }
         let branch = match insn {
            Insn::BCond { target, .. } | Insn::Cbz { target, .. } | Insn::Tbz { target, .. } => {
               Some((target, true))
            },
            Insn::B { target } => Some((target, false)),
            Insn::Ret | Insn::Br { .. } => break,
            _ => None,
         };
         step(&mut regs, insn);
         if let Some((target, falls_through)) = branch {
            if let Ok(to) = body.binary_search_by_key(&target, |&(pc, _)| pc) {
               work.push((to, regs));
            }
            if !falls_through {
               break;
            }
         }
         index += 1;
      }
   }
   calls
      .into_iter()
      .map(|(pc, (target, regs))| (pc, target, regs))
      .collect()
}

/// Field name to offset in a `Debug::fmt` that calls `DebugStruct::field`
/// with `x1`/`w2` the name, `x3` `self + offset` and `x4` the field's `Debug`
/// vtable, with nested structs as `outer.inner`, followed through the
/// vtable's `fmt` `depth` deep. The `field` call is the one most calls in
/// the function go to with that shape.
fn debug_offsets(image: &Image<'_>, func: usize, depth: usize) -> HashMap<String, usize> {
   let mut out = HashMap::new();
   let Some((_, body)) = arm64::function(image, func) else {
      return out;
   };
   let entry: Regs = std::array::from_fn(|at| (at == 0).then_some(Held::SelfAt(0)));
   let calls = calls_with_regs(&body, &entry)
      .into_iter()
      .filter_map(|(_, target, regs)| {
         let (name, len, offset) = pick!(in (regs[1], regs[2], regs[3]),
            (Some(Held::Addr(name) | Held::Page(name)), Some(Held::Imm(len)), Some(Held::SelfAt(offset)))
               => (name, len, offset)
         )?;
         let bytes = usize::try_from(len)
            .ok()
            .filter(|bytes| (1..64).contains(bytes))?;
         let vtable = regs[4].and_then(pick!(Held::Addr(vtable) | Held::Page(vtable) => vtable));
         Some((target, name, bytes, offset, vtable))
      })
      .collect::<Vec<_>>();
   let Some(field_fn) = most_common(calls.iter().map(|&(target, ..)| target), 1) else {
      return out;
   };
   for (target, name_at, bytes, offset, vtable) in calls {
      let text = image
         .read(name_at, bytes)
         .and_then(|text| std::str::from_utf8(text).ok());
      let Some(name) = text.filter(|name| target == field_fn && !out.contains_key(*name)) else {
         continue;
      };
      out.insert(name.to_owned(), offset);
      let fmt = vtable.and_then(|vtable| image.read_usize(vtable + 0x18));
      if depth > 0
         && let Some(fmt) = fmt.filter(|&fmt| image.is_function(fmt))
      {
         for (inner, at) in debug_offsets(image, fmt, depth - 1) {
            out.entry(format!("{name}.{inner}")).or_insert(offset + at);
         }
      }
   }
   out
}

/// `<StyleRefinement as Debug>::fmt`'s fields, from the one function that
/// loads the bare name and prints `padding` and `gap`.
pub fn style_fields(image: &Image<'_>) -> Found<HashMap<String, usize>> {
   let mut found = loaders(image, &image.find_bytes(b"StyleRefinement"))
      .into_iter()
      .map(|func| debug_offsets(image, func, 1))
      .filter(|fields| fields.contains_key("padding.top") && fields.contains_key("gap.width"))
      .collect::<Vec<_>>();
   match found.len() {
      1 => Ok(found.remove(0)),
      count => Err(format!("StyleRefinement Debug matched {count} functions")),
   }
}

/// What `phoenix.ui.addMessageAction` needs from `MessageContextMenu` on
/// arm64: the builder, where its input holds the message and channel ids,
/// and the `MenuItem` constructors its items are made with.
#[derive(Debug, Clone, Copy)]
pub struct MessageMenu {
   /// `fn(x0 input, x1 cx, x2..x5, d0) -> Vec<MenuItem>` through `x8`.
   pub build_fn:          usize,
   /// The input field holding `&Message`.
   pub message:           usize,
   pub message_id_offset: usize,
   pub channel_id_offset: usize,
   /// `props_new(x8 out, x0 &SharedString, w1, w2)`.
   pub props_new:         usize,
   /// `with_id(x8 out, x0 item, x1 ptr, x2 len)`.
   pub with_id:           usize,
   /// `with_icon(x8 out, x0 item, w1 icon)`.
   pub with_icon:         usize,
   /// `with_color(x8 out, x0 item, w1 color)`, which Discord calls with 2
   /// (danger) on destructive actions.
   pub with_color:        Option<usize>,
   /// `Vec<MenuItem>::push(x0 vec, x1 item)`.
   pub vec_push:          usize,
   /// `MenuItem::Separator`'s tag, from a push of an item that is only a tag.
   pub separator_tag:     Option<u64>,
   pub layout:            MenuLayout,
}

fn flattened(image: &Image<'_>, func: usize) -> Vec<Insn> {
   flattened_at(image, func)
      .into_iter()
      .map(|(_, insn)| insn)
      .collect()
}

/// `fn`'s instructions with each outlined stub inlined: a `bl` to a short
/// frameless stub becomes the stub's instructions, and its tail `b T` a `bl T`.
/// A stub's instructions carry its call's address.
#[must_use]
pub fn flattened_at(image: &Image<'_>, func: usize) -> Vec<(usize, Insn)> {
   let Some((_, body)) = arm64::function(image, func) else {
      return Vec::new();
   };
   let mut out = Vec::with_capacity(body.len());
   for (pc, insn) in body {
      let Some((prefix, tail)) = calls(&[insn]).next().and_then(|target| stub(image, target))
      else {
         out.push((pc, insn));
         continue;
      };
      out.extend(prefix.into_iter().map(|insn| (pc, insn)));
      out.extend(tail.map(|tail| (pc, Insn::Bl { target: tail })));
   }
   out
}

/// A stub's instructions before its `b T` (with `T`) or `ret` (without).
fn stub(image: &Image<'_>, at: usize) -> Option<(Vec<Insn>, Option<usize>)> {
   const MOST: usize = 6;
   let mut prefix = Vec::new();
   for (_, insn) in arm64::decode_all(image.read(at, MOST * 4)?, at) {
      match insn {
         Insn::B { target } => return Some((prefix, Some(target))),
         Insn::Ret => return Some((prefix, None)),
         Insn::Bl { .. }
         | Insn::BCond { .. }
         | Insn::Cbz { .. }
         | Insn::Tbz { .. }
         | Insn::Br { .. }
         | Insn::Blr { .. }
         | Insn::Writeback { .. } => return None,
         other => prefix.push(other),
      }
   }
   None
}

/// `stp`/`ldp` of 64-bit registers at a signed offset: `(load, rt, rt2, rn,
/// offset)`.
fn pair(insn: Insn) -> Option<(bool, u8, u8, u8, isize)> {
   let Insn::Other(word) = insn else {
      return None;
   };
   let load = match word & 0xFFC0_0000 {
      0xA900_0000 => false,
      0xA940_0000 => true,
      _ => return None,
   };
   let field = |shift: u32| ((word >> shift) & 31) as u8;
   let imm = (((word >> 15) & 0x7F) << 25).cast_signed() >> 25;
   Some((load, field(0), field(10), field(5), imm as isize * 8))
}

/// The most common value occurring at least `least` times.
fn most_common(values: impl IntoIterator<Item = usize>, least: usize) -> Option<usize> {
   let mut counts = HashMap::<usize, usize>::new();
   for value in values {
      *counts.entry(value).or_default() += 1;
   }
   counts
      .into_iter()
      .filter(|&(_, count)| count >= least)
      .max_by_key(|&(value, count)| (count, std::cmp::Reverse(value)))
      .map(|(value, _)| value)
}

/// [`MessageMenu`], from the builder that loads the bare `MessageContextMenu`
/// name.
///
/// Its items are built `i18n label -> MenuItem::new::<F> -> with_id ->
/// [with_icon] -> push`, every step behind outlined stubs, and each
/// `MenuItem::new::<F>` ends in a core that runs `props_new`, boxes the
/// closure in an `Rc`, copies the props in and writes the variant tag.
#[expect(clippy::too_many_lines, reason = "one pass per located part")]
pub fn message_context_menu(image: &Image<'_>) -> Found<MessageMenu> {
   let builders = loaders(image, &image.find_bytes(b"MessageContextMenu"));
   let build_fn = one("MessageContextMenu builder", &builders)?;
   let body = flattened(image, build_fn);

   // The input arrives in `x0` and is kept in a callee-saved register. The
   // builder loads the ids as one pair, the channel's then the message's.
   let head = &body[..body.len().min(48)];
   let input = head
      .iter()
      .find_map(pick!(&Insn::MovReg { rd, rm: 0, wide: true } if rd >= 19 => rd))
      .ok_or("MessageContextMenu input register not found")?;
   let channel_id_offset = head
      .iter()
      .find_map(|&insn| {
         pair(insn).and_then(pick!(
            (true, _, _, rn, offset) if rn == input && (0x20..=0x400).contains(&offset)
               => usize::try_from(offset).ok()?
         ))
      })
      .ok_or("MessageContextMenu id load not found")?;
   // The builder clones the message out of the input first, passing the field
   // holding `&Message` as `add x0, x0, #message`, then a store, then `bl
   // clone`.
   let message = head
      .windows(3)
      .find_map(pick!(
         &[Insn::AddImm { rd: 0, rn, imm }, Insn::Other(_), Insn::Bl { .. }]
            if (rn == 0 || rn == input) && (0x20..0x400).contains(&imm) => imm
      ))
      .ok_or("MessageContextMenu message field not found")?;

   let calls_after = |want: fn(&Insn) -> bool| {
      let calls = body
         .windows(2)
         .filter_map(pick!(&[before, Insn::Bl { target }] if want(&before) => target));
      calls.collect::<Vec<_>>()
   };
   let id_calls = calls_after(|insn| matches!(insn, Insn::MovZ { rd: 2, .. }));
   let with_id = most_common(id_calls, 3).ok_or("MenuItem::with_id not found")?;

   // `with_icon` keeps the icon as a `u16` on its stack: `sturh w1, [..]`.
   let stores_icon = |func: usize| {
      let code = image.read(func, 8 * 4).unwrap_or_default();
      words(code).any(|word| word & 0xFFE0_0C1F == 0x7800_0001)
   };
   let mut icon_calls = calls_after(|insn| matches!(insn, Insn::MovZ { rd: 1, .. }));
   icon_calls.retain(|&target| stores_icon(target));
   let with_icon = most_common(icon_calls, 2).ok_or("MenuItem::with_icon not found")?;

   // `push` strides by the item size: `mov w9, #size; madd x0, len, x9, ptr`.
   let push_stride = |func: usize| {
      flattened(image, func).windows(2).find_map(pick!(
         &[Insn::MovZ { rd: 9, imm, .. }, Insn::Other(word)]
            if word & 0xFFE0_8000 == 0x9B00_0000 && (word >> 16) & 31 == 9
               => usize::try_from(imm).ok()?
      ))
   };
   let pushes = calls(&body).filter(|&target| push_stride(target).is_some());
   let vec_push = most_common(pushes, 3).ok_or("Vec<MenuItem>::push not found")?;
   let size = push_stride(vec_push).ok_or("Vec<MenuItem>::push stride not found")?;

   // `with_color` sits between `with_icon` and `push`, called with `mov w1, #2`
   // (danger) on destructive actions.
   let mut after_icon = HashMap::<usize, bool>::new();
   let indexed_calls: Vec<(usize, usize)> = body
      .iter()
      .enumerate()
      .filter_map(|(at, insn)| pick!(in *insn, Insn::Bl { target } => (at, target)))
      .collect();
   for window in indexed_calls.windows(3) {
      let [(_, icon), (at, setter), (_, push)] = window else {
         continue;
      };
      if *icon != with_icon || *push != vec_push || *setter == with_icon {
         continue;
      }
      let danger = matches!(body.get(at - 1), Some(Insn::MovZ { rd: 1, imm: 2, .. }));
      *after_icon.entry(*setter).or_insert(true) &= danger;
   }
   let with_color = match after_icon
      .into_iter()
      .filter_map(|(setter, danger)| danger.then_some(setter))
      .collect::<Vec<_>>()
      .as_slice()
   {
      &[only] => Some(only),
      _ => None,
   };

   // Each `MenuItem::new::<F>` reaches its core through
   // `mov x3, x1; mov w1, #0; b core`.
   let mut cores = Vec::new();
   for ctor in sorted(calls(&body).collect::<Vec<_>>()) {
      let code = flattened(image, ctor);
      cores.extend(code.windows(3).filter_map(pick!(
         &[Insn::MovReg { rd: 3, rm: 1, .. }, Insn::MovZ { rd: 1, imm: 0, .. }, Insn::Bl { target }]
            => target
      )));
   }
   let read_core = |core: usize| -> Option<(usize, MenuLayout)> {
      let code = flattened(image, core);
      let props_new = code
         .windows(2)
         .find_map(pick!(&[Insn::AddImm { rd: 8, rn: 31, .. }, Insn::Bl { target }] => target))?;
      let (props, props_size) = code.windows(4).find_map(pick!(
         &[
            Insn::AddImm { rd: 0, rn, imm: props },
            Insn::AddImm { rd: 1, rn: 31, .. },
            Insn::MovZ { rd: 2, imm: props_size, .. },
            Insn::Bl { .. },
         ] if rn != 31 => (props, usize::try_from(props_size).ok()?)
      ))?;
      let mut tagged = code.windows(3).filter_map(pick!(
         &[handler, Insn::MovZ { rd: 8, imm: tag, .. }, variant] => (handler, tag, variant)
      ));
      let (on_click, action_tag) = tagged.find_map(|(handler, tag, variant)| {
         let ((false, _, 8, base, on_click), (false, 8, 31, variant_base, 0)) =
            (pair(handler)?, pair(variant)?)
         else {
            return None;
         };
         (base == variant_base).then_some((usize::try_from(on_click).ok()?, tag))
      })?;
      Some((props_new, MenuLayout {
         size,
         props,
         props_size,
         action_tag,
         on_click,
         on_click_tag: on_click.checked_sub(8)?,
      }))
   };
   let decoded = sorted(cores)
      .into_iter()
      .filter_map(read_core)
      .collect::<Vec<_>>();
   let Some(&(props_new, layout)) = decoded.first() else {
      return Err("no MenuItem::new core decodes".to_owned());
   };
   let key = |at: &MenuLayout| (at.props, at.props_size, at.action_tag, at.on_click);
   let agree = decoded
      .iter()
      .all(|(other, at)| *other == props_new && key(at) == key(&layout));
   if decoded.len() < 2 || !agree {
      return Err(format!("{} MenuItem::new cores disagree", decoded.len()));
   }
   if layout.props + layout.props_size > layout.size
      || layout.on_click + 16 > layout.props
      || layout.size > layout::SCRATCH_CAP
   {
      return Err(format!("MenuItem layout doesn't fit: {layout:x?}"));
   }
   Ok(MessageMenu {
      build_fn,
      message,
      message_id_offset: channel_id_offset + 8,
      channel_id_offset,
      props_new,
      with_id,
      with_icon,
      with_color,
      vec_push,
      separator_tag: separator_tag(image, vec_push, layout.action_tag),
      layout,
   })
}

/// The tag of the payload-less `MenuItem` other menus push. Just before the
/// call, `mov wT, #tag; str xT, [sp, #slot]; ...; add x1, sp, #slot` with
/// nothing else stored in the slot. Every such push must agree.
fn separator_tag(image: &Image<'_>, vec_push: usize, action_tag: u64) -> Option<u64> {
   let tags = refs_to(image, &[vec_push])
      .into_iter()
      .filter_map(|(site, _)| {
         let insns = decoded(image, site.checked_sub(8 * 4)?, 8);
         let slot = insns.iter().rev().find_map(|insn| {
            match *insn {
               Insn::AddImm { rd: 1, rn: 31, imm } => Some(imm),
               _ => None,
            }
         })?;
         let stores: Vec<_> = insns
            .iter()
            .filter_map(|insn| {
               match *insn {
                  Insn::Store {
                     rt, rn: 31, offset, ..
                  } if (slot..slot + 0x200).contains(&offset) => Some((rt, offset)),
                  _ => None,
               }
            })
            .collect();
         let &[(rt, offset)] = stores.as_slice() else {
            return None;
         };
         if offset != slot {
            return None;
         }
         insns
            .iter()
            .rev()
            .find_map(|insn| {
               match *insn {
                  Insn::MovZ { rd, imm, .. } if rd == rt => Some(imm),
                  _ => None,
               }
            })
            .filter(|&tag| tag < 0x10 && tag != action_tag)
      });
   match sorted(tags.collect()).as_slice() {
      &[tag] => Some(tag),
      _ => None,
   }
}

/// An address loaded by an `adrp`/`add` pair, at each instruction that
/// completes one, in a [`flattened_at`] stream.
fn loaded(insns: &[(usize, Insn)]) -> Vec<Option<(u8, usize)>> {
   let mut regs: Regs = [None; 32];
   insns
      .iter()
      .map(|&(_, insn)| {
         let out = match insn {
            Insn::AddImm { rd, rn, imm } if rn != 31 => {
               pick!(in regs[usize::from(rn)], Some(Held::Page(page)) => (rd, page + imm))
            },
            _ => None,
         };
         step(&mut regs, insn);
         out
      })
      .collect()
}

/// `<Message as Serialize>::serialize` into a `serde_json` writer, and the
/// allocator's free for the bytes it writes.
#[derive(Debug, Clone, Copy)]
pub struct MessageWriter {
   /// `fn(x0 &Message, x1 &mut Serializer<&mut Vec<u8>>) -> x0
   /// Option<Box<Error>>`.
   pub serialize:  usize,
   /// `__rust_dealloc(x0 ptr, x1 size, x2 align)`.
   pub dealloc:    usize,
   /// The message's id, the first field it writes.
   pub message_id: usize,
}

/// [`MessageWriter`].
///
/// The serializer is the one function loading `"mention_everyone"` whose
/// first strings are `{` and the `id` key, with `channel_id` and `guild_id`
/// keys and no `kind`. It moves its base once (`ldr xT, [xB, #w]!`)
/// and passes `&message.id` as `add x3, xB, #id`. The free is the call
/// `String` drops end in, `mov w2, #1; b dealloc`.
pub fn message_writer(image: &Image<'_>) -> Found<MessageWriter> {
   let found = loaders(image, &image.find_bytes(b"mention_everyone"))
      .into_iter()
      .filter_map(|func| {
         let code = flattened_at(image, func);
         let loads = loaded(&code);
         let strings = loads
            .iter()
            .flatten()
            .filter_map(|&(_, addr)| image.read(addr, 16))
            .collect::<Vec<_>>();
         let [open, id, ..] = strings.as_slice() else {
            return None;
         };
         let has = |key: &[u8]| strings.iter().any(|text| text.starts_with(key));
         if !(open.starts_with(b"{")
            && id.starts_with(b"id")
            && has(b"channel_id")
            && has(b"guild_id")
            && !has(b"kind"))
         {
            return None;
         }
         let (moved, base) = code.iter().take(16).find_map(pick!(
            &(_, Insn::Writeback { rn, imm, load: true, .. }) => (usize::try_from(imm).ok()?, rn)
         ))?;
         let (id_at, _) = loads
            .iter()
            .enumerate()
            .filter(|(_, load)| load.is_some())
            .nth(1)?;
         let field = code[id_at..]
            .iter()
            .take(6)
            .find_map(pick!(&(_, Insn::AddImm { rd: 3, rn, imm }) if rn == base => imm))?;
         Some((func, moved + field))
      })
      .collect::<Vec<_>>();
   let &[(serialize, message_id)] = found.as_slice() else {
      return Err(format!("{} Message serializers", found.len()));
   };

   let mut tails = HashMap::<usize, usize>::new();
   // `mov w2, #1` or `mov x2, #1`.
   for (pc, _) in code_words(image).filter(|&(_, word)| word & 0x7FFF_FFFF == 0x5280_0022) {
      if let Some(Insn::B { target }) = decode_at(image, pc + 4) {
         *tails.entry(target).or_default() += 1;
      }
   }
   let mut ranked = tails.into_iter().collect::<Vec<_>>();
   ranked.sort_unstable_by_key(|&(_, count)| std::cmp::Reverse(count));
   // 613 against 60 for the runner-up on 2233.
   let dealloc = match ranked[..] {
      [(dealloc, most), (_, next), ..] if most >= next * 4 => dealloc,
      _ => return Err("__rust_dealloc not found".to_owned()),
   };
   Ok(MessageWriter {
      serialize,
      dealloc,
      message_id,
   })
}

fn calls(code: &[Insn]) -> impl Iterator<Item = usize> + '_ {
   code
      .iter()
      .filter_map(pick!(&Insn::Bl { target } => target))
}

/// `div_child_div`'s push of the child onto `self.children`: `add x0, xS,
/// #children`, the element into `x1`, then the call. The offset and `push`.
fn children_push(code: &[Insn]) -> Option<(usize, usize)> {
   code.windows(3).find_map(pick!(
      &[Insn::AddImm { rd: 0, rn, imm }, Insn::Bl { target }, ..]
         | &[Insn::AddImm { rd: 0, rn, imm }, _, Insn::Bl { target }]
         if rn != 31 => (imm, target)
   ))
}

/// The first register `code` copies `source` into.
fn copy_of(code: &[Insn], source: u8) -> Option<u8> {
   code
      .iter()
      .find_map(pick!(&Insn::MovReg { rd, rm, .. } if rm == source => rd))
}

/// `(after, x0, x1, target)` for each `mov w0, #x0; mov w1, #x1; bl target`.
fn allocs(code: &[Insn]) -> impl Iterator<Item = (usize, u64, u64, usize)> + '_ {
   code.windows(3).enumerate().filter_map(|(at, window)| {
      pick!(in *window,
         [Insn::MovZ { rd: 0, imm: x0, .. }, Insn::MovZ { rd: 1, imm: x1, .. }, Insn::Bl { target }]
            => (at + 3, x0, x1, target)
      )
   })
}

/// The `Rc<dyn Fn>` a handler setter stores, and the size of what it returns:
/// it allocates the `Rc` (`mov w0, #8; mov w1, #size; bl alloc`), stores it
/// into its copy of `self`, and copies that out (`mov w2, #size; b memcpy`).
fn handler_store(image: &Image<'_>, setter: usize) -> Option<(usize, usize)> {
   let code = flattened(image, setter);
   let (alloc, ..) = allocs(&code).find(|&(_, size, ..)| size == 8)?;
   let tail = &code[alloc..];
   let boxed = copy_of(tail, 0)?;
   let offset = tail
      .iter()
      .find_map(pick!(&Insn::Store { rt, offset, size: 8, .. } if rt == boxed => offset))?;
   // An epilogue `ldp` may sit between the size and the tail call.
   let size = tail.windows(3).find_map(pick!(
      &[Insn::MovZ { rd: 2, imm, .. }, Insn::B { .. } | Insn::Bl { .. }, _]
         | &[Insn::MovZ { rd: 2, imm, .. }, _, Insn::B { .. } | Insn::Bl { .. }] => imm
   ))?;
   Some((offset, usize::try_from(size).ok()?))
}

/// Where a `Switch` setter keeps its `Option<SharedString>`: it reads the tag
/// with a writeback load off `self` (`ldrb w8, [x23, #off]!`) and checks it for
/// `None` (`cmp w8, #0xff`). Some monomorphizations wrap the setter of the
/// `Switch`'s leading field struct, which keeps the same offsets, so a setter
/// without the load is read through its first call.
fn option_string_field(image: &Image<'_>, setter: usize) -> Option<usize> {
   let code = flattened(image, setter);
   let tagged_load = |code: &[Insn]| {
      let mut selves = vec![0u8];
      for (index, &insn) in code.iter().enumerate() {
         selves.extend(pick!(in insn, Insn::MovReg { rd, rm, .. } if selves.contains(&rm) => rd));
         let Some((rt, imm)) = pick!(in insn,
            Insn::Writeback { rt, rn, imm, load: true } if selves.contains(&rn) && imm > 0
               => (rt, imm)
         ) else {
            continue;
         };
         let mut following = code[index + 1..].iter().take(2);
         if following.any(|next| matches!(*next, Insn::CmpImm { rn, imm: 0xff, .. } if rn == rt)) {
            return Some(imm.unsigned_abs());
         }
      }
      None
   };
   tagged_load(&code)
      .or_else(|| calls(&code).find_map(|target| tagged_load(&flattened(image, target))))
}

/// The bytes Discord stores into a constructor's result right after calling
/// it, most common first, as `(count, offset)`.
///
/// The result is the stack slot `x8` points at (`add x8, sp, #base`); a store
/// lands at `sp + base + field`, directly or through a register set to `sp + k`
/// after the call.
#[must_use]
fn post_ctor_byte_stores(image: &Image<'_>, ctor: usize, size: usize) -> Vec<(usize, usize)> {
   let mut counts = HashMap::<usize, usize>::new();
   for func in loaders(image, &[ctor]) {
      let code = flattened_at(image, func);
      for (at, &(_, insn)) in code.iter().enumerate() {
         if insn != (Insn::Bl { target: ctor }) {
            continue;
         }
         let Some(base) = code[at.saturating_sub(12)..at]
            .iter()
            .rev()
            .find_map(pick!(&(_, Insn::AddImm { rd: 8, rn: 31, imm }) => imm))
         else {
            continue;
         };
         let mut regs: Regs = [None; 32];
         regs[31] = Some(Held::SelfAt(0));
         let mut seen = std::collections::HashSet::new();
         for &(_, insn) in code[at + 1..].iter().take(14) {
            if matches!(insn, Insn::Bl { .. } | Insn::B { .. }) {
               break;
            }
            if let Insn::Store {
               rn,
               offset,
               size: 1,
               ..
            } = insn
               && let Some(Held::SelfAt(from)) = regs[usize::from(rn)]
               && let Some(field) = (from + offset)
                  .checked_sub(base)
                  .filter(|&field| field < size)
               && seen.insert(field)
            {
               *counts.entry(field).or_default() += 1;
            }
            step(&mut regs, insn);
         }
      }
   }
   let mut ranked = counts
      .into_iter()
      .map(|(field, count)| (count, field))
      .collect::<Vec<_>>();
   ranked.sort_unstable_by(|a, b| b.cmp(a));
   ranked
}

/// [`GpuiLayout`] for arm64, from the builders [`crate::locate::gpui::gpui`] found.
pub fn gpui_layouts(image: &Image<'_>, gpui: &Gpui) -> Found<GpuiLayout> {
   // `div_child_div` pushes the child at `self + children`, then copies `self`
   // out through its `x8` copy field by field; the last store is the end.
   let child = flattened(image, gpui.div_child_div);
   let (children, _) = children_push(&child).ok_or("Div children SmallVec offset not found")?;
   let out = copy_of(&child, 8).ok_or("div_child_div result register not found")?;
   let div_size = child
      .iter()
      .filter_map(pick!(
         &Insn::Store { rn, offset, size, .. } if rn == out => offset + size,
         &Insn::Other(word)
            if word & 0xFFC0_0000 == 0xAD00_0000 && (word >> 5) & 31 == u32::from(out) => {
            let imm = (((word >> 15) & 0x7F) << 25).cast_signed() >> 25;
            usize::try_from(imm * 16 + 32).ok()?
         },
      ))
      .max()
      .ok_or("Div size not found")?;

   // `div_new` boxes `Interactivity` (`mov w0, #size; mov w1, #8; bl`) and
   // stores the box in its result with an `stp`.
   let new = flattened(image, gpui.div_new);
   let (interactivity_size, boxed_at) = allocs(&new)
      .find_map(pick!(
         (after, size, 8, _) if (0x100..0x2000).contains(&size)
            => (usize::try_from(size).ok()?, after)
      ))
      .ok_or("Div::new Interactivity allocation not found")?;
   let boxed = copy_of(&new[boxed_at..], 0).ok_or("Div::new Interactivity register not found")?;
   let interactivity = new[boxed_at..]
      .iter()
      .find_map(|&insn| {
         pair(insn).and_then(pick!(
            (false, rt, _, _, offset) if rt == boxed => usize::try_from(offset).ok()?,
            (false, _, rt2, _, offset) if rt2 == boxed => usize::try_from(offset + 8).ok()?,
         ))
      })
      .ok_or("Div::new Interactivity store not found")?;
   if children + 0x48 > div_size || interactivity + 8 > div_size || div_size > layout::DIV_CAP {
      return Err(format!("Div fields don't fit (size {div_size:#x})"));
   }

   // `Interactivity::default` boxes the `StyleRefinement`.
   let style_bytes = calls(&new)
      .find_map(|callee| {
         let mut head = flattened(image, callee);
         head.truncate(40);
         allocs(&head).find_map(pick!(
            (_, size, 8, _) if (0x200..=0x400).contains(&size) => usize::try_from(size).ok()?
         ))
      })
      .ok_or("Interactivity::default StyleRefinement allocation not found")?;
   let style = crate::desktop::style_from_fields(&style_fields(image)?, style_bytes)?;

   let (on_change, switch_size) =
      handler_store(image, gpui.switch_on_change).ok_or("Switch::on_change Rc store not found")?;
   let label = option_string_field(image, gpui.switch_label).ok_or("Switch::label not found")?;
   let description =
      option_string_field(image, gpui.switch_desc).ok_or("Switch::description not found")?;
   if label.max(description) + 24 > switch_size
      || on_change + 16 > switch_size
      || switch_size > layout::SCRATCH_CAP
   {
      return Err("Switch fields sit past the Switch".to_owned());
   }

   let (on_click, button_size) =
      handler_store(image, gpui.button_on_click).ok_or("Button::on_click Rc store not found")?;
   if on_click + 16 > button_size || button_size > layout::SCRATCH_CAP {
      return Err("Button on_click sits past the Button".to_owned());
   }
   // The variant is the byte set most often after `Button::new`, the size the
   // next (666 and 117 stores, then 37, on 2026-11 builds). When that isn't
   // clear, both are left past the scratch buffer so the runtime skips them.
   let (variant, scale) = match post_ctor_byte_stores(image, gpui.button_new, button_size)[..] {
      [(top, variant), (second, scale), ref rest @ ..]
         if top >= 3 * second && rest.first().is_none_or(|&(third, _)| second >= 3 * third) =>
      {
         (variant, scale)
      },
      _ => (layout::SCRATCH_CAP, layout::SCRATCH_CAP),
   };

   Ok(GpuiLayout {
      style,
      div: DivLayout {
         size: div_size,
         children,
         interactivity,
         interactivity_size,
      },
      switch: SwitchLayout {
         size: switch_size,
         label,
         description,
         on_change,
      },
      button: ButtonLayout {
         size: button_size,
         on_click,
         variant,
         scale,
      },
   })
}

/// The body of `<ClientAccessGate as ClientSelector>::read` after its
/// prologue: `mov x19, x2; mov x20, x0; bl enforced; cbz w0, open; ldr x1,
/// [x19, #ready]; add x8, sp, #8; mov x0, x20; mov w2, #1; bl access_at; ldrb
/// w20, [sp, #8]`, then the drop and `open: mov w20, #2; mov x0, x20`.
///
/// Read on build 2233. The `ldr`'s field offset and the calls are wildcards.
const ACCESS_GATE: Pattern = Pattern::new(
   "F3 03 02 AA F4 03 00 AA ?? ?? ?? ?? ?? ?? 00 34 61 ?? ?? F9 E8 23 00 91 E0 03 14 AA 22 00 80 \
    52 ?? ?? ?? ?? F4 23 40 39 E8 13 40 B9 ?? ?? ?? 36 E1 0F 40 F9 ?? ?? ?? ?? ?? ?? ?? 14 54 00 \
    80 52 E0 03 14 AA",
);

/// The prologue's four instructions before [`ACCESS_GATE`].
const PROLOGUE_LEN: usize = 16;

/// `<ClientAccessGate as ClientSelector>::read`, `u8 read(..)` where 2 is
/// "no gate", the value it answers when access is not enforced.
pub fn access_read(image: &Image<'_>) -> Found<usize> {
   let body = one("access read", &image.scan(ACCESS_GATE))?;
   let entry = body
      .checked_sub(PROLOGUE_LEN)
      .ok_or("access gate: the body has no prologue")?;
   // `sub sp, sp, #imm` opens the frame.
   match image.read(entry, 4) {
      Some(&[a, b, c, d]) if u32::from_le_bytes([a, b, c, d]) & 0xFFC0_03FF == 0xD100_03FF => {
         Ok(entry)
      },
      _ => Err(format!("access gate at {entry:#x} does not open a frame")),
   }
}

/// `client_access::enforced` after its frame: `ldr x8, [x0]; add x0, x8,
/// #state; bl; ldrb w8, [x0, #flag]; mov w9, #1; bic w0, w9, w8`, then the
/// frame's `ldp` and `ret`.
///
/// Read on build 2233. The two offsets and the call are wildcards.
const ENFORCED: Pattern = Pattern::new(
   "FD 7B BF A9 FD 03 00 91 08 00 40 F9 00 ?? ?? 91 ?? ?? ?? ?? 08 ?? ?? 39 29 00 80 52 20 01 28 \
    0A FD 7B C1 A8 C0 03 5F D6",
);

/// [`ENFORCED`]'s length in bytes.
const ENFORCED_LEN: usize = 40;

/// Offset of `bl enforced` in [`ACCESS_GATE`].
const ENFORCED_CALL: usize = 8;

/// `client_access::enforced`, `bool enforced(..)`, the first call of the
/// [`access_read`] function. `push_access` reads it too, without
/// going through `read`, and drops every message alert while it is true.
pub fn access_enforced(image: &Image<'_>, read: usize) -> Found<usize> {
   let call = read + PROLOGUE_LEN + ENFORCED_CALL;
   let enforced = image
      .read_u32(call)
      .filter(|bl| bl & 0xFC00_0000 == 0x9400_0000)
      .map(|bl| {
         // imm26 counts instructions, sign-extended.
         let words = ((bl << 6).cast_signed() >> 6) as isize;
         call.wrapping_add_signed(words * 4)
      })
      .ok_or_else(|| format!("access gate at {read:#x} does not call enforced"))?;
   match image.read(enforced, ENFORCED_LEN) {
      Some(body) if ENFORCED.find_in(body) == [0] => Ok(enforced),
      _ => Err(format!("enforced at {enforced:#x} has changed")),
   }
}

/// `mov w0, #0; ret`: returns `false` from `pages_under_frame`.
pub const PAGES_OVER_FRAME: [u8; 8] = [0x00, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6];

/// `discord_desktop_platform::webview::pages_under_frame` on macOS.
///
/// Release builds ignore `LIBDISCORD_MAC_PAGES_OVER_FRAME`, so callers of the
/// helper that logs `"webview: ordered under the window's frame"` gate it with
/// `bl pages_under_frame; tbz w0, #0, ...`.
pub fn pages_under_frame(image: &Image<'_>) -> Found<usize> {
   const ANCHOR: &[u8] = b"webview: ordered under the window's frame";
   const LOOKBACK: usize = 8;

   let anchor = one("webview under-frame anchor", &image.find_bytes(ANCHOR))?;
   let helper = one("webview under-frame helper", &loaders(image, &[anchor]))?;

   let mut found = Vec::new();
   for (site, _) in refs_to(image, &[helper]) {
      if decode_at(image, site) != Some(Insn::Bl { target: helper }) {
         continue;
      }
      for back in 1..=LOOKBACK {
         let Some(call_pc) = site.checked_sub(back * 4) else {
            break;
         };
         let Some(Insn::Bl { target }) = decode_at(image, call_pc) else {
            continue;
         };
         let branches_on_false = matches!(
            decode_at(image, call_pc + 4),
            Some(
               Insn::Tbz {
                  rt: 0,
                  bit: 0,
                  nonzero: false,
                  ..
               } | Insn::Cbz {
                  rt: 0,
                  nonzero: false,
                  ..
               }
            )
         );
         if branches_on_false && image.is_function(target) {
            found.push(target);
            break;
         }
      }
   }
   one("pages_under_frame", &sorted(found))
}

/// Locates `libdiscord_gateway`'s `SocketSink::start_send` vtable slot and
/// `Ok(())` niche tag on macOS arm64.
pub fn gateway_send(image: &Image<'_>) -> Found<crate::gateway_send::DesktopGatewaySend> {
   use crate::gateway_send::{
      ADOPT_ANCHOR,
      DesktopGatewaySend,
      START_SEND_PANIC,
      START_SEND_SLOT_OFFSET,
      find_sink_slots,
      sink_vtable_start_send,
   };

   if image.pointer_width != 8 {
      return Err("not a 64-bit image".to_owned());
   }
   let anchor = one("gateway adopt anchor", &image.find_bytes(ADOPT_ANCHOR))?;
   let (site, _) = one("gateway adopt anchor load", &refs_to(image, &[anchor]))?;
   let (_, open_code) =
      arm64::function(image, site).ok_or("gateway connect_adopting has no unwind entry")?;

   let panic_addrs = image.find_bytes(START_SEND_PANIC);
   if panic_addrs.is_empty() {
      return Err("start_send panic string not found".to_owned());
   }

   let mut matches = Vec::new();
   for (_, vtable) in loaded(&open_code).into_iter().flatten() {
      let Some(start_send) = sink_vtable_start_send(image, vtable) else {
         continue;
      };
      let Some((_, ss_code)) = arm64::function(image, start_send) else {
         continue;
      };
      if !loaded(&ss_code)
         .into_iter()
         .flatten()
         .any(|(_, target)| panic_addrs.contains(&target))
      {
         continue;
      }
      let Some(ok_tag) = arm64_start_send_ok_tag(&ss_code) else {
         continue;
      };
      matches.push((vtable, start_send, ok_tag));
   }
   matches.sort_unstable();
   matches.dedup_by_key(|&mut (_, start_send, _)| start_send);
   let (vtable, start_send_fn, ok_tag) = one("SocketSink vtable", &matches)?;

   let mut start_send_slots = find_sink_slots(image, start_send_fn);
   let direct = vtable + START_SEND_SLOT_OFFSET;
   if !start_send_slots.contains(&direct) {
      start_send_slots.push(direct);
   }
   start_send_slots.sort_unstable();

   Ok(DesktopGatewaySend {
      start_send_slots,
      start_send_fn,
      ok_tag,
   })
}

/// Decodes the `Ok(())` niche discriminant (`u64::MAX - 1` or `u64::MAX`) that
/// `SocketSink::start_send` writes to `[sret, #0]` before returning.
fn arm64_start_send_ok_tag(code: &[(usize, Insn)]) -> Option<u64> {
   let sret = code
      .iter()
      .take(16)
      .find_map(pick!(&(_, Insn::MovReg { rd, rm: 8, wide: true }) => rd))
      .unwrap_or(8);
   let mut known = [None::<u64>; 32];
   for &(_, insn) in code {
      match insn {
         Insn::MovN {
            rd,
            imm,
            wide: true,
         } => {
            known[usize::from(rd)] = Some(!imm);
         },
         Insn::Store {
            rt,
            rn,
            offset: 0,
            size: 8,
         } if rn == sret => {
            if let Some(tag @ (0xFFFF_FFFF_FFFF_FFFE | 0xFFFF_FFFF_FFFF_FFFF)) =
               known[usize::from(rt)]
            {
               return Some(tag);
            }
         },
         Insn::Load { rt, .. } | Insn::MovZ { rd: rt, .. } | Insn::MovReg { rd: rt, .. } => {
            known[usize::from(rt)] = None;
         },
         _ => {},
      }
   }
   None
}

/// The arm64 branch that skips building the composer's Nitro gift button.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComposerGift {
   pub site:   usize,
   pub shown:  u32,
   pub hidden: u32,
}

/// Locates the conditional branch that skips the composer's Nitro gift button
/// on macOS arm64.
pub fn composer_gift(image: &Image<'_>) -> Found<ComposerGift> {
   let ids = image.find_bytes(b"gift-button.wrap");
   let refs = refs_to(image, &ids);
   let (id, _) = one("gift button id", &refs)?;
   let (_, code) = arm64::function(image, id).ok_or("gift button has no function bounds")?;
   let after_id = code
      .iter()
      .position(|&(pc, _)| pc == id)
      .ok_or("gift button id not in function")?;
   let window = &code[after_id..(after_id + 128).min(code.len())];
   let (slot, after) = window
      .windows(3)
      .find_map(|triple| {
         match (triple[0].1, triple[1].1, triple[2].1) {
            (
               Insn::MovZ { rd, imm: 1, .. },
               Insn::Store {
                  rt,
                  rn: 31,
                  offset,
                  size: 8,
               },
               Insn::B { target },
            ) if rt == rd => Some((offset, target)),
            _ => None,
         }
      })
      .ok_or("gift button stores no Some")?;
   let none = after.checked_sub(4).ok_or("gift button jumps to 0")?;
   let none_word = image
      .read_u32(none)
      .ok_or("gift button None store is unmapped")?;
   match arm64::decode(none_word, none) {
      Insn::Store {
         rt: 31,
         rn: 31,
         offset,
         size: 8,
      } if offset == slot => {},
      _ => return Err(format!("gift button jumps to {after:#x}, after no None store")),
   }
   let (site, target) = code
      .iter()
      .take_while(|&&(pc, _)| pc < none)
      .find_map(|&(pc, insn)| {
         let (Insn::BCond { target, .. } | Insn::Cbz { target, .. } | Insn::Tbz { target, .. }) =
            insn
         else {
            return None;
         };
         (none.saturating_sub(0x20)..=none)
            .contains(&target)
            .then_some((pc, target))
      })
      .ok_or_else(|| format!("no branch skips the gift button before {none:#x}"))?;
   let shown = image
      .read_u32(site)
      .ok_or("gift button branch is unmapped")?;
   let delta = target.cast_signed() - site.cast_signed();
   if delta % 4 != 0 || !(-(1 << 27)..(1 << 27)).contains(&delta) {
      return Err(format!("gift button branch at {site:#x} out of B range"));
   }
   #[expect(
      clippy::cast_possible_truncation,
      clippy::cast_sign_loss,
      reason = "checked 26-bit signed word offset"
   )]
   let hidden = 0x1400_0000 | (((delta >> 2) as u32) & 0x03FF_FFFF);
   Ok(ComposerGift {
      site,
      shown,
      hidden,
   })
}

/// Locates `Interactivity::mouse_down_listeners`, `Vec::push`,
/// `Hitbox::is_hovered`, and `App::propagate_event` on macOS arm64 (for
/// `phoenix.ui.onEvent("rowDoubleTap")` and modal dismissal).
pub fn mouse_down(image: &Image<'_>, div: &DivLayout) -> Found<crate::desktop::Dismiss> {
   const ARENA_PANIC: &[u8] =
      b"attempted to dereference an ArenaRef after its Arena was cleared";
   let panics = image.find_bytes(ARENA_PANIC);
   let accessors = sorted(
      refs_to(image, &panics)
         .into_iter()
         .filter_map(|(site, _)| {
            let (func, code) = arm64::function(image, site)?;
            if code.len() > 24 {
               return None;
            }
            let reads_interactivity = code.windows(2).any(|pair| {
               matches!(
                  (pair[0].1, pair[1].1),
                  (
                     Insn::Load {
                        rt: 0,
                        rn: 0,
                        offset,
                        size: 8,
                     },
                     Insn::Ret,
                  ) if offset == div.interactivity
               )
            });
            reads_interactivity.then_some(func)
         })
         .collect(),
   );
   if accessors.is_empty() {
      return Err("Div::interactivity not found".to_owned());
   }

   let mut by_vec: HashMap<usize, (usize, crate::desktop::Dismiss)> = HashMap::new();
   for &interactivity in &accessors {
      for (site, _) in refs_to(image, &[interactivity]) {
         let Some((_, code)) = arm64::function(image, site) else {
            continue;
         };
         let Some(at) = code.iter().position(|&(pc, _)| pc == site) else {
            continue;
         };
         let Some(callee) = code[at + 1..(at + 6).min(code.len())]
            .iter()
            .find_map(pick!(&(_, Insn::Bl { target }) => target))
         else {
            continue;
         };
         let Some(dismiss) = arm64_on_mouse_down_shape(image, callee, div.interactivity_size)
         else {
            continue;
         };
         let entry = by_vec
            .entry(dismiss.mouse_down_listeners)
            .or_insert((0, dismiss));
         entry.0 += 1;
      }
   }
   let mut ranked: Vec<(usize, crate::desktop::Dismiss)> = by_vec.into_values().collect();
   ranked.sort_unstable_by_key(|a| std::cmp::Reverse(a.0));
   let Some(&(top_count, best)) = ranked.first() else {
      return Err("arm64 Interactivity::on_mouse_down not found".to_owned());
   };
   if ranked.iter().any(|&(_, d)| {
      d.hitbox_is_hovered != best.hitbox_is_hovered || d.propagate_event != best.propagate_event
   }) {
      return Err(format!("arm64 on_mouse_down helpers disagree: {ranked:x?}"));
   }
   if ranked
      .get(1)
      .is_some_and(|&(next, _)| top_count < 3 * next)
   {
      return Err(format!("arm64 on_mouse_down is ambiguous: {ranked:x?}"));
   }
   Ok(best)
}

fn arm64_on_mouse_down_shape(
   image: &Image<'_>,
   func: usize,
   interactivity_size: usize,
) -> Option<crate::desktop::Dismiss> {
   let (_, code) = arm64::function(image, func)?;
   if code.len() > 24 {
      return None;
   }
   let vtable = loaded(&code)
      .into_iter()
      .flatten()
      .rev()
      .find_map(|(rd, addr)| (rd == 2).then_some(addr))?;
   let mouse_down_listeners = code.iter().find_map(pick!(
      &(_, Insn::AddImm { rd: 0, rn, imm }) if rn != 31 && imm > 0 && imm + 0x18 <= interactivity_size => imm
   ))?;
   let mut push = code.iter().rev().find_map(pick!(
      &(_, Insn::B { target } | Insn::Bl { target }) => target
   ))?;
   if let Some((_, stub)) = arm64::function(image, push)
      && stub.len() <= 4
      && let Some(&(_, Insn::B { target })) = stub.last()
   {
      push = target;
   }
   if !image.is_code(push) {
      return None;
   }

   let call = image.read_usize(vtable + 0x28)?;
   let (_, wrapper) = arm64::function(image, call)?;
   let checks_phase = wrapper
      .iter()
      .take(4)
      .any(|&(_, insn)| matches!(insn, Insn::Cbz { rt: 2, nonzero: true, .. }));
   if !checks_phase {
      return None;
   }
   let reads_button = wrapper.iter().any(|&(_, insn)| {
      matches!(
         insn,
         Insn::Load {
            rn: 1,
            offset: 0x10,
            size: 1,
            ..
         }
      )
   });
   if !reads_button {
      return None;
   }
   let (hitbox_is_hovered, propagate_event) = wrapper.windows(5).find_map(|w| {
      match (w[0].1, w[1].1, w[2].1, w[3].1, w[4].1) {
         (
            Insn::MovReg {
               rd: 0,
               rm: 3,
               wide: true,
            },
            Insn::MovReg {
               rd: 1,
               rm: 4,
               wide: true,
            },
            Insn::Bl { target },
            Insn::Cbz {
               rt: 0,
               nonzero: false,
               ..
            },
            Insn::Store {
               rt: 31,
               offset,
               size: 1,
               ..
            },
         ) if image.is_code(target) && offset < 0x10000 => Some((target, offset)),
         _ => None,
      }
   })?;
   Some(crate::desktop::Dismiss {
      mouse_down_listeners,
      listener_push: push,
      hitbox_is_hovered,
      propagate_event,
   })
}

/// [`crate::desktop::svg_builders`] for macOS arm64.
pub fn svg_builders(image: &Image<'_>) -> Found<crate::desktop::SvgBuilders> {
   const BUNDLED_SVG: &[u8] = b"features_ui/platform-spotify.svg";
   let anchors = image.find_bytes(BUNDLED_SVG);
   let mut draws: Vec<(usize, usize)> = refs_to(image, &anchors)
      .into_iter()
      .filter_map(|(site, _)| Some((image.function_bounds(site)?.0, site)))
      .collect();
   draws.dedup_by_key(|&mut (func, _)| func);
   let (func, lea) = one("bundled SVG draw", &draws)?;
   let (_, code) = arm64::function(image, func).ok_or("SVG icon function unreadable")?;
   let at = code
      .iter()
      .position(|&(pc, _)| pc == lea)
      .ok_or("SVG path load not decoded")?;
   let new = code[..at]
      .iter()
      .rev()
      .find_map(pick!(&(_, Insn::Bl { target }) => target))
      .ok_or("svg() call not found")?;
   let after: Vec<usize> = code[at..]
      .iter()
      .filter_map(pick!(&(_, Insn::Bl { target }) => target))
      .collect();
   let path = *after.first().ok_or("Svg::path call not found")?;
   let style_box = after
      .iter()
      .skip(1)
      .take(6)
      .find_map(|&callee| {
         let (_, head) = arm64::function(image, callee)?;
         head.iter().take(8).find_map(pick!(
            &(_, Insn::Load { rn: 0 | 1, offset, size: 8, .. }) if (0x100..0x800).contains(&offset) => offset
         ))
      })
      .ok_or("Svg style box not found")?;
   let into_any = code[at..]
      .windows(2)
      .rev()
      .find_map(|pair| {
         match (pair[0].1, pair[1].1) {
            (
               Insn::MovReg {
                  rd: 8,
                  wide: true,
                  ..
               },
               Insn::Bl { target },
            ) => Some(target),
            _ => None,
         }
      })
      .ok_or("Svg::into_any call not found")?;
   let (_, into_code) = arm64::function(image, into_any).ok_or("Svg::into_any unreadable")?;
   let size = into_code
      .iter()
      .take(16)
      .find_map(pick!(&(_, Insn::MovZ { rd: 2, imm, .. }) => usize::try_from(imm).ok()?))
      .filter(|&size| (style_box..0x1000).contains(&size))
      .ok_or("Svg size not found")?;
   Ok(crate::desktop::SvgBuilders {
      new,
      path,
      into_any,
      size,
      style_box,
   })
}

/// [`crate::desktop::asset_load`] for macOS arm64.
pub fn asset_load(image: &Image<'_>) -> Found<usize> {
   const BUNDLED_SVG: &[u8] = b"features_ui/platform-spotify.svg";
   let record = |slot: usize| {
      let ptr = image.read_usize(slot)?;
      let len = image.read_usize(slot + 8)?;
      let index = image.read_usize(slot + 16)?;
      let path = image
         .read(ptr, len)
         .filter(|_| (3..=200).contains(&len) && index < 100_000)?;
      path
         .iter()
         .all(|byte| byte.is_ascii_alphanumeric() || b"/._-".contains(byte))
         .then_some(())
   };
   let mut slots = image
      .find_bytes(BUNDLED_SVG)
      .into_iter()
      .flat_map(|string| image.pointers_to(string))
      .filter(|&slot| {
         image.read_usize(slot + 8) == Some(BUNDLED_SVG.len()) && record(slot).is_some()
      })
      .collect::<Vec<_>>();
   slots.dedup();
   let mut start = one("bundled SVG record", &slots)?;
   while let Some(previous) = start.checked_sub(24)
      && record(previous).is_some()
   {
      start = previous;
   }
   let descriptors = image
      .pointers_to(start)
      .into_iter()
      .filter(|&descriptor| !refs_to(image, &[descriptor]).is_empty())
      .collect::<Vec<_>>();
   let descriptor = one("asset bundle", &descriptors)?;
   let found = sorted(
      refs_to(image, &[descriptor])
         .into_iter()
         .filter_map(|(site, _)| {
            let (func, code) = arm64::function(image, site)?;
            (code.len() >= 64).then_some(func)
         })
         .collect(),
   );
   one("asset loader", &found)
}

/// Message header hooks for macOS arm64 (`phoenix.ui.addMessageHeaderDecoration`).
#[derive(Clone, Copy, Debug)]
pub struct MessageHeader {
   /// The author-name wrapper builder called only by the header row builders.
   pub name_producer: usize,
   /// `child_node(node, child) -> node` adding a non-optional child handle.
   pub child_node:    usize,
   /// Node SVG leaf constructor and pusher.
   pub svg:           crate::desktop::NodeSvg,
}

/// Locates [`MessageHeader`] on macOS arm64.
#[expect(
   clippy::too_many_lines,
   reason = "locates child_node, name producer, svg_new, and push_svg together"
)]
pub fn message_header(image: &Image<'_>) -> Found<MessageHeader> {
   const HEADER_APP_TAG: &[u8] = b"\x0fheader-app-tag-\xc0\x00";
   const NODE_SVG: &[u8] = b"features_ui/partner.svg";

   let anchor = one("header-app-tag template", &image.find_bytes(HEADER_APP_TAG))?;
   let builders = loaders(image, &[anchor]);
   if !(2..=crate::desktop::MAX_HEADER_BUILDERS).contains(&builders.len()) {
      return Err(format!(
         "the app tag template is loaded by {} functions",
         builders.len()
      ));
   }

   let is_child_node = |func: usize| {
      let Some((_, code)) = arm64::function(image, func) else {
         return false;
      };
      if code.len() > 16 {
         return false;
      }
      code.windows(2).any(|pair| {
         matches!(
            (pair[0].1, pair[1].1),
            (
               Insn::Store {
                  rt: 31,
                  rn: 31,
                  offset: 0,
                  size: 4,
               },
               Insn::Store {
                  rt: 1,
                  rn: 31,
                  offset: 8,
                  size: 8,
               },
            )
         )
      })
   };

   let mut child_nodes = Vec::new();
   let mut builder_callees: Vec<std::collections::HashSet<usize>> = Vec::new();
   for &builder in &builders {
      let mut set = std::collections::HashSet::new();
      for (_, insn) in flattened_at(image, builder) {
         if let Insn::Bl { target } | Insn::B { target } = insn {
            set.insert(target);
            if is_child_node(target) {
               child_nodes.push(target);
            }
            if let Some((_, stub)) = arm64::function(image, target)
               && stub.len() <= 6
               && let Some(&(_, Insn::B { target: tail })) = stub.last()
               && is_child_node(tail)
            {
               child_nodes.push(tail);
            }
         }
      }
      builder_callees.push(set);
   }
   let child_node = one("header child_node", &sorted(child_nodes))?;

   let all: std::collections::HashSet<usize> = builders.iter().copied().collect();
   let mut producers = Vec::new();
   for &callee in &builder_callees[0] {
      if !builder_callees[1..].iter().all(|set| set.contains(&callee)) {
         continue;
      }
      let Some((_, code)) = arm64::function(image, callee) else {
         continue;
      };
      if code.len() < 32 {
         continue;
      }
      let callers = loaders(image, &[callee]);
      if !callers.is_empty()
         && callers.iter().all(|c| all.contains(c))
         && builders
            .iter()
            .all(|&builder| feeds_child_node(image, builder, callee, child_node))
      {
         producers.push(callee);
      }
   }
   let name_producer = one("header name producer", &sorted(producers))?;

   let mut svg_news = Vec::new();
   for (site, _) in refs_to(image, &image.find_bytes(NODE_SVG)) {
      let Some((_, code)) = arm64::function(image, site) else {
         continue;
      };
      let Some(at) = code.iter().position(|&(pc, _)| pc == site) else {
         continue;
      };
      let Some(callee) = code[at + 1..(at + 8).min(code.len())]
         .iter()
         .find_map(pick!(&(_, Insn::Bl { target }) => target))
      else {
         continue;
      };
      let Some((_, body)) = arm64::function(image, callee) else {
         continue;
      };
      let Some(path_off) = body.iter().find_map(pick!(
         &(_, Insn::AddImm { rd: 8, rn: 8, imm }) if imm >= 8 => imm
      )) else {
         continue;
      };
      let has_zero_color = body.iter().any(|&(_, insn)| {
         matches!(
            insn,
            Insn::Store {
               rt: 31,
               offset,
               size: 4,
               ..
            } if (4..path_off).contains(&offset)
         )
      });
      if body.len() <= 24 && has_zero_color {
         svg_news.push(callee);
      }
   }
   let svg_new = one("node svg_new", &sorted(svg_news))?;

   let mut pushes: Vec<(usize, usize)> = Vec::new();
   let mut colors: Vec<usize> = Vec::new();
   for (site, _) in refs_to(image, &[svg_new]) {
      let Some((_, code)) = arm64::function(image, site) else {
         continue;
      };
      let Some(at) = code.iter().position(|&(pc, _)| pc == site) else {
         continue;
      };
      let leaf = code[at.saturating_sub(8)..at]
         .iter()
         .rev()
         .find_map(pick!(&(_, Insn::AddImm { rd: 8, rn: 31, imm }) => imm));
      for (delta, &(_, insn)) in code[at + 1..(at + 12).min(code.len())].iter().enumerate() {
         let Insn::Bl { target } = insn else {
            continue;
         };
         let Some((_, body)) = arm64::function(image, target) else {
            continue;
         };
         // An outlined color-setter stub between `svg_new` and `push_svg`
         // stores `mov wT, #1` at `[sp, #leaf + color]` (str or 32-bit stp).
         if let Some(leaf) = leaf
            && delta < 4
            && body.len() <= 16
            && let Some(off) = svg_color_tag_offset(&body, leaf)
         {
            colors.push(off);
         }
         if body.len() > 160 {
            continue;
         }
         let leaf_size = body.windows(3).find_map(|w| {
            match (w[0].1, w[1].1, w[2].1) {
               (
                  Insn::MovZ { rd: 0, imm, .. },
                  Insn::MovZ { rd: 1, imm: 8, .. },
                  Insn::Bl { .. },
               ) => usize::try_from(imm).ok().filter(|&s| (0x20..=0x100).contains(&s)),
               _ => None,
            }
         });
         let saves_x1 = body.iter().take(10).any(|&(_, i)| {
            matches!(
               i,
               Insn::MovReg {
                  rm: 1,
                  wide: true,
                  ..
               }
            )
         });
         if let Some(size) = leaf_size
            && saves_x1
         {
            if let Some(leaf) = leaf
               && let Some(off) = svg_color_tag_offset(&code[at + 1..at + 1 + delta], leaf)
            {
               colors.push(off);
            }
            pushes.push((target, size));
         }
      }
   }
   let push_svg =
      most_common(pushes.iter().map(|&(func, _)| func), 2).ok_or("node push_svg not found")?;
   let leaf_size = pushes
      .iter()
      .find_map(|&(func, size)| (func == push_svg).then_some(size))
      .ok_or("node SVG leaf size not found")?;
   let (_, svg_new_body) = arm64::function(image, svg_new).ok_or("node svg_new has no bounds")?;
   let color_off = one(
      "node svg color offset",
      &sorted(
         colors
            .into_iter()
            .filter(|&off| {
               (4..leaf_size.saturating_sub(4)).contains(&off)
                  && svg_new_body.iter().any(|&(_, insn)| {
                     matches!(
                        insn,
                        Insn::Store {
                           rt: 31,
                           offset,
                           size: 4,
                           ..
                        } if offset == off
                     )
                  })
            })
            .collect(),
      ),
   )?;

   Ok(MessageHeader {
      name_producer,
      child_node,
      svg: crate::desktop::NodeSvg {
         new:   svg_new,
         push:  push_svg,
         color: color_off,
         size:  leaf_size,
      },
   })
}

/// Decodes a `mov wT, #1` stored to `[sp, #leaf + color]` via 32-bit `str` or
/// `stp` in `insns`, returning `color`.
fn svg_color_tag_offset(insns: &[(usize, Insn)], leaf: usize) -> Option<usize> {
   let mut regs: Regs = [None; 32];
   for &(_, insn) in insns {
      match insn {
         Insn::Store {
            rt,
            rn: 31,
            offset,
            size: 4,
         } if regs[usize::from(rt)] == Some(Held::Imm(1)) => {
            if let Some(rel) = offset.checked_sub(leaf).filter(|&r| (4..0x30).contains(&r)) {
               return Some(rel);
            }
         },
         Insn::Other(word) if word & 0xFFC0_0000 == 0x2900_0000 => {
            // 32-bit `stp wt, wt2, [rn, #imm7*4]`
            let rt = (word & 31) as u8;
            let rn = ((word >> 5) & 31) as u8;
            let imm = ((((word >> 15) & 0x7F) << 25).cast_signed() >> 25) * 4;
            if rn == 31
               && regs[usize::from(rt)] == Some(Held::Imm(1))
               && let Ok(offset) = usize::try_from(imm)
               && let Some(rel) = offset.checked_sub(leaf).filter(|&r| (4..0x30).contains(&r))
            {
               return Some(rel);
            }
         },
         _ => {},
      }
      step(&mut regs, insn);
   }
   None
}

/// Whether `builder` passes `producer`'s `x0` result into `child_node`'s `x1`
/// argument (directly or via a 1-step register/stack save and outlined stub).
fn feeds_child_node(image: &Image<'_>, builder: usize, producer: usize, child_node: usize) -> bool {
   #[derive(Clone, Copy, PartialEq, Eq)]
   enum Place {
      Reg(u8),
      Stack(usize),
   }

   let Some((_, code)) = arm64::function(image, builder) else {
      return false;
   };
   let mut saved = Vec::new();
   for (at, &(_, insn)) in code.iter().enumerate() {
      if insn != (Insn::Bl { target: producer }) {
         continue;
      }
      for &(_, next) in code[at + 1..].iter().take(6) {
         if let Some((false, rt, rt2, 31, off)) = pair(next) {
            if let Ok(off) = usize::try_from(off) {
               if rt == 0 {
                  saved.push(Place::Stack(off));
               }
               if rt2 == 0 {
                  saved.push(Place::Stack(off + 8));
               }
            }
            continue;
         }
         match next {
            Insn::MovReg {
               rd,
               rm: 0,
               wide: true,
            } => saved.push(Place::Reg(rd)),
            Insn::Store {
               rt: 0,
               rn: 31,
               offset,
               size: 8,
            } => saved.push(Place::Stack(offset)),
            Insn::Bl { .. } | Insn::B { .. } => break,
            _ => {},
         }
      }
   }
   if saved.is_empty() {
      return false;
   }

   let x1_source = |insns: &[(usize, Insn)]| -> Option<Place> {
      for &(_, insn) in insns.iter().rev() {
         if let Some((true, rt, rt2, 31, off)) = pair(insn)
            && let Ok(off) = usize::try_from(off)
         {
            if rt == 1 {
               return Some(Place::Stack(off));
            }
            if rt2 == 1 {
               return Some(Place::Stack(off + 8));
            }
         }
         match insn {
            Insn::MovReg {
               rd: 1,
               rm,
               wide: true,
            } => return Some(Place::Reg(rm)),
            Insn::Load {
               rt: 1,
               rn: 31,
               offset,
               size: 8,
            } => return Some(Place::Stack(offset)),
            Insn::Bl { .. } | Insn::B { .. } => break,
            _ => {},
         }
      }
      None
   };

   for (at, &(_, insn)) in code.iter().enumerate() {
      let Insn::Bl { target } = insn else {
         continue;
      };
      let source = if target == child_node {
         x1_source(&code[at.saturating_sub(6)..at])
      } else if let Some((_, stub)) = arm64::function(image, target)
         && stub.len() <= 6
         && matches!(stub.last(), Some(&(_, Insn::B { target: tail })) if tail == child_node)
      {
         x1_source(&stub[..stub.len() - 1]).or_else(|| x1_source(&code[at.saturating_sub(6)..at]))
      } else {
         None
      };
      if source.is_some_and(|place| saved.contains(&place)) {
         return true;
      }
   }
   false
}

/// The member list's row renderer and its name-row closure on macOS arm64.
///
/// `name_closure` has ABI `(sret: *mut Div, row: *mut Div, env: *const u8)` and
/// adds the member's name (plain or styled) to `row`, returning the row `Div`
/// before subsequent closures append bot/clan badges. `*(env + env_user_id)` is
/// `*const u64` pointing to the member's user id.
#[derive(Clone, Copy, Debug)]
pub struct MemberRow {
   pub func:         usize,
   pub name_closure: usize,
   pub env_user_id:  usize,
}

/// Locates [`MemberRow`] on macOS arm64.
pub fn member_row(image: &Image<'_>) -> Found<MemberRow> {
   let anchors = image.find_bytes(b"member-{}-{}");
   let func = one("member row", &loaders(image, &anchors))?;
   let (_, code) = arm64::function(image, func).ok_or("member row unreadable")?;

   let template = refs_to(image, &anchors)
      .into_iter()
      .find_map(|(site, _)| code.iter().position(|&(pc, _)| pc == site))
      .ok_or("member row template load not found")?;
   let id_slot = code[template.saturating_sub(8)..template]
      .iter()
      .rev()
      .find_map(pick!(
         &(_, Insn::Load { rt: 2, rn: 31, offset, size: 8 }) => offset
      ))
      .ok_or("member row id slot not found")?;

   let mut matches = Vec::new();
   for (at, &(_, insn)) in code.iter().enumerate() {
      let Insn::AddImm {
         rd: id_reg,
         rn: 31,
         imm,
      } = insn
      else {
         continue;
      };
      if imm != id_slot {
         continue;
      }
      let window = &code[at + 1..(at + 40).min(code.len())];
      let mut stored_at = Vec::new();
      for (i, &(_, step)) in window.iter().enumerate() {
         match step {
            Insn::Store {
               rt,
               rn: 31,
               offset,
               size: 8,
            } if rt == id_reg => stored_at.push(offset),
            Insn::AddImm {
               rd: 1,
               rn: 31,
               imm: env_base,
            } => {
               let Some(Insn::Bl { target: closure }) = window.get(i + 1).map(|&(_, x)| x) else {
                  continue;
               };
               for &field in &stored_at {
                  let Some(env_off) = field.checked_sub(env_base) else {
                     continue;
                  };
                  if env_off > 0x80 {
                     continue;
                  }
                  if closure_reads_env_user(image, closure, env_off) {
                     matches.push((closure, env_off));
                  }
               }
            },
            Insn::MovReg { rd, .. }
            | Insn::AddImm { rd, .. }
            | Insn::Load { rt: rd, .. }
            | Insn::MovZ { rd, .. }
               if rd == id_reg =>
            {
               break;
            },
            _ => {},
         }
      }
   }
   let (name_closure, env_user_id) = one("member name closure", &sorted(matches))?;
   Ok(MemberRow {
      func,
      name_closure,
      env_user_id,
   })
}

/// Whether `closure` is a non-tiny function taking `(sret: x8, row: x0, env: x1)`
/// that dereferences `*(env + env_off)` to read a `u64` user id.
fn closure_reads_env_user(image: &Image<'_>, closure: usize, env_off: usize) -> bool {
   let Some((_, raw)) = arm64::function(image, closure) else {
      return false;
   };
   if raw.len() < 100 {
      return false;
   }
   let flat = flattened_at(image, closure);
   let Some(env_reg) = flat.iter().take(24).find_map(pick!(
      &(_, Insn::MovReg { rd, rm: 1, wide: true }) if (19..=28).contains(&rd) => rd
   )) else {
      return false;
   };
   flat.windows(2).any(|pair| {
      matches!(
         (pair[0].1, pair[1].1),
         (
            Insn::Load {
               rt: ptr_reg,
               rn,
               offset,
               size: 8,
            },
            Insn::Load {
               rn: deref,
               offset: 0,
               size: 8,
               ..
            },
         ) if rn == env_reg && offset == env_off && deref == ptr_reg
      )
   })
}

/// The DM list's row renderer, its name-box builder, and `Div::child::<AnyElement>`
/// on macOS arm64.
#[derive(Clone, Copy, Debug)]
pub struct DmRow {
   pub func:          usize,
   pub name_box:      usize,
   pub div_child_any: usize,
   pub props_some:    usize,
   pub props_user:    usize,
}

/// Locates [`DmRow`] on macOS arm64.
pub fn dm_row(image: &Image<'_>) -> Found<DmRow> {
   let box_anchors = image.find_bytes(b"dm-name-bounds");
   let name_box = one("DM name box", &loaders(image, &box_anchors))?;
   let func = one("DM row", &loaders(image, &[name_box]))?;

   let (_, row_code) = arm64::function(image, func).ok_or("DM row unreadable")?;
   let (_, box_code) = arm64::function(image, name_box).ok_or("DM name box unreadable")?;
   let status_anchors = image.find_bytes(b"dm-status");
   let status_at = refs_to(image, &status_anchors)
      .into_iter()
      .find_map(|(site, _)| row_code.iter().position(|&(pc, _)| pc == site))
      .ok_or("DM row does not load dm-status")?;

   let user_slot = row_code[status_at..row_code.len().min(status_at + 10)]
      .iter()
      .find_map(pick!(&(_, Insn::Load { rn: 31, offset, size: 8, .. }) => offset))
      .ok_or("DM recipient user slot not found")?;

   let (props_some, props_user) = row_code
      .windows(2)
      .find_map(|w| {
         let (true, a, b, props_reg, base_off) = pair(w[0].1)? else {
            return None;
         };
         let (false, s1, s2, 31, sp_off) = pair(w[1].1)? else {
            return None;
         };
         if props_reg == 31 || base_off < 0 || sp_off < 0 {
            return None;
         }
         let base_off = usize::try_from(base_off).ok()?;
         let sp_off = usize::try_from(sp_off).ok()?;
         if sp_off == user_slot && s1 == b && s2 == a {
            Some((base_off, base_off + 8))
         } else if sp_off == user_slot && s1 == a && s2 == b {
            Some((base_off + 8, base_off))
         } else {
            None
         }
      })
      .ok_or("DM props Option<UserId> layout not decoded")?;

   let box_callees: std::collections::HashSet<usize> = box_code
      .iter()
      .filter_map(pick!(&(_, Insn::Bl { target }) => target))
      .collect();
   let call_at = row_code
      .iter()
      .position(|&(_, insn)| insn == Insn::Bl { target: name_box })
      .ok_or("DM name box call not found")?;
   let div_child_cands = sorted(
      row_code[call_at + 1..(call_at + 40).min(row_code.len())]
         .iter()
         .filter_map(|&(_, insn)| {
            let Insn::Bl { target } = insn else {
               return None;
            };
            if !box_callees.contains(&target) {
               return None;
            }
            let (_, body) = arm64::function(image, target)?;
            let saves_x0 = body.iter().take(10).any(|&(_, i)| {
               matches!(
                  i,
                  Insn::MovReg {
                     rm: 0,
                     wide: true,
                     ..
                  }
               )
            });
            let saves_x8 = body.iter().take(10).any(|&(_, i)| {
               matches!(
                  i,
                  Insn::MovReg {
                     rm: 8,
                     wide: true,
                     ..
                  }
               )
            });
            (body.len() <= 64 && saves_x0 && saves_x8).then_some(target)
         })
         .collect(),
   );
   let div_child_any = one("DM Div::child<AnyElement>", &div_child_cands)?;

   Ok(DmRow {
      func,
      name_box,
      div_child_any,
      props_some,
      props_user,
   })
}

/// [`crate::desktop::settings_layer`] for macOS arm64.
pub fn settings_layer(image: &Image<'_>) -> Found<usize> {
   const LITERAL_REACH: usize = 512;
   let trap = one("layer-trap- literal", &image.find_bytes(b"layer-trap-"))?;
   let range = trap.saturating_sub(LITERAL_REACH)..trap + 1;
   let loads = arm64::code_refs(image, std::slice::from_ref(&range));
   let start = loads.iter().map(|&(_, target)| target).max();
   let funcs = sorted(
      loads
         .into_iter()
         .filter(|&(_, target)| Some(target) == start)
         .filter_map(|(site, _)| Some(image.function_bounds(site)?.0))
         .filter(|&func| {
            arm64::function(image, func).is_some_and(|(_, code)| {
               loaded(&code)
                  .into_iter()
                  .flatten()
                  .any(|(_, target)| image.read(target, 14) == Some(b"settings-layer".as_slice()))
            })
         })
         .collect(),
   );
   one("settings layer render", &funcs)
}

/// Locates a hosted `into_any_element` function from its type-name literal on
/// arm64, returning `(func, element_size)`.
fn arm64_into_any(image: &Image<'_>, type_name: &[u8]) -> Found<(usize, usize)> {
   let hits = image.find_bytes(type_name);
   let mut found = Vec::new();
   for (site, _) in refs_to(image, &hits) {
      let Some((func, code)) = arm64::function(image, site) else {
         continue;
      };
      if code.len() > 64 {
         continue;
      }
      let size = code.windows(2).find_map(|pair| {
         match (pair[0].1, pair[1].1) {
            (
               Insn::MovZ {
                  rd: 2,
                  imm,
                  wide: false,
               },
               Insn::Bl { .. },
            ) => usize::try_from(imm).ok().filter(|&s| (0x40..0x2000).contains(&s)),
            _ => None,
         }
      });
      if let Some(size) = size {
         found.push((func, size));
      }
   }
   one(
      std::str::from_utf8(type_name).unwrap_or("into_any"),
      &sorted(found),
   )
}

/// Whether `func`'s flattened body copies `size` bytes (`mov w2, #size`).
fn copies_size(image: &Image<'_>, func: usize, size: usize) -> bool {
   let Ok(want) = u64::try_from(size) else {
      return false;
   };
   flattened_at(image, func).iter().any(|&(_, insn)| {
      matches!(
         insn,
         Insn::MovZ {
            rd: 2,
            imm,
            wide: false,
         } if imm == want
      )
   })
}

/// The best of `ranked` (`(count, value)`, sorted down) if it beats the
/// runner-up `margin` times over.
fn clear_winner(what: &str, ranked: &[(usize, usize)], margin: usize) -> Found<usize> {
   match ranked {
      [(top, value), rest @ ..] if rest.first().is_none_or(|&(next, _)| *top >= margin * next) => {
         Ok(*value)
      },
      _ => Err(format!(
         "{what} is ambiguous ({:x?})",
         &ranked[..ranked.len().min(4)]
      )),
   }
}

/// [`crate::desktop::modal`] for macOS arm64.
#[expect(
   clippy::too_many_lines,
   reason = "locates and cross-checks overlay_render, Modal builders, Div::id, dismiss, and layout"
)]
pub fn modal(
   image: &Image<'_>,
   div_into_any: usize,
   div: &DivLayout,
) -> Found<crate::desktop::Modal> {
   const MODAL_TYPE: &[u8] = b"mana_html::hosted::modal::Modal";
   const BUTTON_TYPE: &[u8] = b"mana_gpui::components::button::Button";

   let overlay_str = one(
      "nav-overlay-popout-layer",
      &image.find_bytes(b"nav-overlay-popout-layer"),
   )?;
   let (overlay_site, _) = one("nav-overlay-popout-layer load", &refs_to(image, &[overlay_str]))?;
   let (overlay_render, _) = image
      .function_bounds(overlay_site)
      .ok_or("Workspace::render_overlays has no bounds")?;

   let mut ranked_new = Vec::new();
   for addr in image.find_bytes(b"mana-modal") {
      if image
         .read(addr + b"mana-modal".len(), 1)
         .is_some_and(|b| b[0] == b'-')
      {
         continue;
      }
      let funcs = sorted(
         refs_to(image, &[addr])
            .into_iter()
            .filter_map(|(site, _)| image.function_bounds(site))
            .collect(),
      );
      if !funcs.iter().any(|&(s, e)| e - s > 0x4000) {
         continue;
      }
      for (start, end) in funcs {
         if end - start <= 0x800 {
            ranked_new.push((refs_to(image, &[start]).len(), start));
         }
      }
   }
   ranked_new.sort_unstable_by(|a, b| b.cmp(a));
   ranked_new.dedup();
   let modal_new = clear_winner("Modal::new", &ranked_new, 4)?;

   let (modal_into_any, modal_size) = arm64_into_any(image, MODAL_TYPE)?;
   let (button_into_any, _) = arm64_into_any(image, BUTTON_TYPE)?;

   let mut footers = Vec::new();
   for (site, _) in refs_to(image, &[button_into_any]) {
      let Some((start, end)) = image.function_bounds(site) else {
         continue;
      };
      if end - start > 0x180 || !copies_size(image, start, modal_size) {
         continue;
      }
      let flat = flattened_at(image, start);
      if let Some((vec_off, push_fn)) = modal_vec_push(&flat) {
         footers.push((start, push_fn, vec_off));
      }
   }
   let (modal_footer_button, vec_push_any, footer) = one("Modal::footer_button", &sorted(footers))?;

   let mut div_any_targets = vec![div_into_any];
   for (site, _) in refs_to(image, &[div_into_any]) {
      if let Some((s, code)) = arm64::function(image, site)
         && code.len() == 1
         && matches!(code[0].1, Insn::B { target } if target == div_into_any)
      {
         div_any_targets.push(s);
      }
   }
   let mut push_entries = vec![vec_push_any];
   for (site, _) in refs_to(image, &[vec_push_any]) {
      if let Some((s, code)) = arm64::function(image, site)
         && code.len() <= 4
         && matches!(code.last(), Some(&(_, Insn::B { target })) if target == vec_push_any)
      {
         push_entries.push(s);
      }
   }
   let mut childs = Vec::new();
   for &entry in &push_entries {
      for (site, _) in refs_to(image, &[entry]) {
         let Some((start, end)) = image.function_bounds(site) else {
            continue;
         };
         if start == modal_footer_button
            || end - start > 0x180
            || !copies_size(image, start, modal_size)
         {
            continue;
         }
         let flat = flattened_at(image, start);
         let calls_div_any = flat.iter().any(|&(_, insn)| {
            matches!(insn, Insn::Bl { target } if div_any_targets.contains(&target))
         });
         if !calls_div_any {
            continue;
         }
         if let Some((vec_off, push_fn)) = modal_vec_push(&flat)
            && push_fn == vec_push_any
            && vec_off != footer
         {
            childs.push((start, vec_off));
         }
      }
   }
   let (modal_child_div, children) = one("Modal::child<Div>", &sorted(childs))?;

   let carousel_bytes = b"game-server-shop-carousel";
   let carousel = one("game-server-shop-carousel", &image.find_bytes(carousel_bytes))?;
   let (carousel_site, _) = one("game-server-shop-carousel load", &refs_to(image, &[carousel]))?;
   let (carousel_fn, _) = image
      .function_bounds(carousel_site)
      .ok_or("game-server-shop-carousel caller has no bounds")?;
   let carousel_flat = flattened_at(image, carousel_fn);
   let at = carousel_flat
      .iter()
      .position(|&(pc, _)| pc == carousel_site)
      .ok_or("carousel load not in function")?;
   let div_id = carousel_flat[at + 1..(at + 20).min(carousel_flat.len())]
      .windows(2)
      .find_map(|pair| {
         match (pair[0].1, pair[1].1) {
            (
               Insn::MovZ {
                  rd: 2,
                  imm,
                  wide: false,
               },
               Insn::Bl { target },
            ) if imm == u64::try_from(carousel_bytes.len()).unwrap_or(0) => Some(target),
            _ => None,
         }
      })
      .ok_or("Div::id call after carousel anchor not found")?;
   let (_, div_id_code) = arm64::function(image, div_id).ok_or("Div::id unreadable")?;
   if !div_id_code
      .iter()
      .any(|&(_, insn)| matches!(insn, Insn::CmpImm { imm: 0xFF, .. }))
   {
      return Err("Div::id element_id check failed".to_owned());
   }

   let scale = arm64_modal_scale(image, modal_new, modal_size)?;
   let subtitle = arm64_modal_subtitle(image, modal_new, modal_size)?;
   let on_close = arm64_modal_on_close(image, modal_new, modal_size)?;

   Ok(crate::desktop::Modal {
      overlay_render,
      vec_push_any,
      modal_new,
      modal_into_any,
      modal_child_div,
      modal_footer_button,
      div_id,
      window_validation_offset: 0,
      dismiss: mouse_down(image, div)?,
      layout: crate::desktop::ModalLayout {
         size: modal_size,
         children,
         footer,
         subtitle,
         on_close,
         scale,
      },
   })
}

fn modal_vec_push(flat: &[(usize, Insn)]) -> Option<(usize, usize)> {
   flat.windows(3).find_map(|w| {
      match (w[0].1, w[1].1, w[2].1) {
         (
            Insn::AddImm {
               rd: 0,
               rn: 19,
               imm: off,
            },
            Insn::AddImm {
               rd: 1,
               rn: 31,
               imm: 0,
            },
            Insn::Bl { target } | Insn::B { target },
         ) if off < 0x100 => Some((off, target)),
         _ => None,
      }
   })
}

fn arm64_modal_scale(image: &Image<'_>, modal_new: usize, size: usize) -> Found<usize> {
   let mut counts: HashMap<usize, usize> = HashMap::new();
   for (site, _) in refs_to(image, &[modal_new]) {
      let Some((_, code)) = arm64::function(image, site) else {
         continue;
      };
      let Some(at) = code.iter().position(|&(pc, _)| pc == site) else {
         continue;
      };
      let Some(base) = code[at.saturating_sub(6)..at]
         .iter()
         .rev()
         .find_map(pick!(&(_, Insn::AddImm { rd: 8, rn: 31, imm }) => imm))
      else {
         continue;
      };
      let mut seen = std::collections::HashSet::new();
      for &(_, insn) in &code[at + 1..(at + 12).min(code.len())] {
         match insn {
            Insn::Store {
               rn: 31,
               offset,
               size: 1,
               ..
            } => {
               if let Some(field) = offset.checked_sub(base)
                  && field < size
                  && seen.insert(field)
               {
                  *counts.entry(field).or_default() += 1;
               }
            },
            Insn::Bl { .. } | Insn::B { .. } => break,
            _ => {},
         }
      }
   }
   let mut ranked: Vec<(usize, usize)> = counts.into_iter().map(|(at, n)| (n, at)).collect();
   ranked.sort_unstable_by(|a, b| b.cmp(a));
   clear_winner("Modal scale store", &ranked, 4)
}

fn arm64_modal_subtitle(image: &Image<'_>, modal_new: usize, size: usize) -> Found<usize> {
   let Ok(size_u32) = u32::try_from(size) else {
      return Err("Modal size overflows".to_owned());
   };
   let mov_w2_size = (0x5280_0002u32 | ((size_u32 & 0xFFFF) << 5)).to_le_bytes();
   let funcs = sorted(
      image
         .find_bytes(&mov_w2_size)
         .into_iter()
         .filter(|&at| image.is_code(at))
         .filter_map(|at| image.function_bounds(at))
         .filter(|&(s, e)| e - s <= 0x180 && s != modal_new)
         .map(|(s, _)| s)
         .collect(),
   );

   let mut setters = Vec::new();
   for func in funcs {
      let Some((_, code)) = arm64::function(image, func) else {
         continue;
      };
      let field = code.windows(2).find_map(|pair| {
         match (pair[0].1, pair[1].1) {
            (
               Insn::Load {
                  rt,
                  rn: 0,
                  offset,
                  size: 1,
               },
               Insn::CmpImm {
                  rn,
                  imm: 0xFF,
                  wide: false,
               },
            ) if rt == rn && offset + 24 <= size => Some(offset),
            _ => None,
         }
      });
      let Some(field) = field else {
         continue;
      };
      let writes_tail = code.iter().any(|&(_, insn)| {
         matches!(
            insn,
            Insn::Store {
               offset: 0x10,
               size: 8,
               ..
            }
         )
      });
      if writes_tail {
         setters.push((refs_to(image, &[func]).len(), field));
      }
   }
   setters.sort_unstable_by(|a, b| b.cmp(a));
   clear_winner("Modal subtitle setter", &setters, 2)
}

fn arm64_modal_on_close(image: &Image<'_>, modal_new: usize, size: usize) -> Found<usize> {
   let mut votes: HashMap<usize, usize> = HashMap::new();
   let mut checked = std::collections::HashSet::new();
   for (site, _) in refs_to(image, &[modal_new]) {
      let Some((_, code)) = arm64::function(image, site) else {
         continue;
      };
      let Some(at) = code.iter().position(|&(pc, _)| pc == site) else {
         continue;
      };
      for &(_, insn) in &code[at + 1..(at + 32).min(code.len())] {
         let Insn::Bl { target } = insn else {
            continue;
         };
         if !checked.insert(target) {
            continue;
         }
         let Some((s, e)) = image.function_bounds(target) else {
            continue;
         };
         if e - s > 0x140 || !copies_size(image, s, size) {
            continue;
         }
         let flat = flattened_at(image, s);
         let mut stored_fields = Vec::new();
         for &(_, step) in &flat {
            if let Insn::Store {
               rn: 19,
               offset,
               size: 8,
               ..
            } = step
               && offset + 16 <= size
            {
               stored_fields.push(offset);
            }
         }
         for &field in &stored_fields {
            if stored_fields.contains(&(field + 8)) {
               *votes.entry(field).or_default() += 1;
            }
         }
      }
   }
   let mut ranked: Vec<(usize, usize)> = votes.into_iter().map(|(at, n)| (n, at)).collect();
   ranked.sort_unstable_by(|a, b| b.cmp(a));
   clear_winner("Modal on_close store", &ranked, 4)
}

/// [`crate::desktop::text_fields`] for macOS arm64.
#[expect(
   clippy::too_many_lines,
   reason = "locates and cross-checks FieldState, TextInput, and TextArea together"
)]
pub fn text_fields(image: &Image<'_>) -> Found<crate::desktop::TextFields> {
   const RICH_TEXT_STATE: &[u8] = b"mana_gpui::components::rich_text::state::RichTextState";
   const TEXT_INPUT_TYPE: &[u8] = b"mana_html::hosted::text_input::TextInput";
   const TEXT_AREA_TYPE: &[u8] = b"mana_html::hosted::text_area::TextArea";

   let (ctor_single, ctor_multi, inner, field_slots) = arm64_field_state_new(image)?;

   let (cx_new_single, entity_clone, entity_downgrade, weak_drop) =
      arm64_pick_cx_new(image, ctor_single, inner, "cx.new(FieldState::new)")?;
   let (cx_new_multiline, m_clone, m_down, m_weak) =
      arm64_pick_cx_new(image, ctor_multi, inner, "cx.new(FieldState::new_multiline)")?;
   if entity_clone != m_clone || entity_downgrade != m_down || weak_drop != m_weak {
      return Err("cx.new single/multiline helpers disagree".to_owned());
   }

   let (_, down_code) =
      arm64::function(image, entity_downgrade).ok_or("entity_downgrade unreadable")?;
   let weak_ptr = down_code
      .windows(2)
      .find_map(|pair| {
         match (pair[0].1, pair[1].1) {
            (
               Insn::Load {
                  rt,
                  rn: 0,
                  offset,
                  size: 8,
               },
               Insn::Other(w),
            ) if w & 0xFFFF_FC1F == 0xB100_041F
               && ((w >> 5) & 31) == u32::from(rt)
               && offset + 8 <= layout::ENTITY =>
            {
               Some(offset)
            },
            _ => None,
         }
      })
      .ok_or("WeakEntity Weak offset not found in entity_downgrade")?;

   let rts_addrs = image.find_bytes(RICH_TEXT_STATE);
   if rts_addrs.is_empty() {
      return Err("RichTextState type name not found".to_owned());
   }
   let set_c = loaders(image, &rts_addrs);
   let c_set: std::collections::HashSet<usize> = set_c.iter().copied().collect();

   let app_entities_of = |func: usize| -> Option<(usize, usize)> {
      let (_, code) = arm64::function(image, func)?;
      let head = &code[..code.len().min(16)];
      head.windows(3).find_map(|w| {
         match (w[0].1, w[1].1, w[2].1) {
            (
               Insn::AddImm {
                  rd: 0,
                  rn: 1,
                  imm: entities,
               },
               Insn::MovReg { rd: 1, .. },
               Insn::Bl { target },
            ) if entities < 0x100 => Some((entities, target)),
            _ => None,
         }
      })
   };

   let mut caller_counts: HashMap<usize, usize> = HashMap::new();
   for &func in &set_c {
      let Some((_, code)) = arm64::function(image, func) else {
         continue;
      };
      let mut seen = std::collections::HashSet::new();
      for &(_, insn) in &code {
         if let Insn::Bl { target } = insn
            && target != func
            && c_set.contains(&target)
            && seen.insert(target)
            && app_entities_of(target).is_some()
         {
            *caller_counts.entry(target).or_default() += 1;
         }
      }
   }
   let mut ranked_get: Vec<(usize, usize)> = caller_counts
      .into_iter()
      .filter(|&(_, count)| count >= 3)
      .map(|(func, count)| (count, func))
      .collect();
   ranked_get.sort_unstable_by(|a, b| b.cmp(a));
   let text_get = clear_winner("FieldState text_get", &ranked_get, 2)?;
   let (app_entities, entity_map_get) =
      app_entities_of(text_get).ok_or("App entity map offset not found in text_get")?;
   let (_, text_get_code) = arm64::function(image, text_get).ok_or("text_get unreadable")?;
   let text_get_callees: std::collections::HashSet<usize> = text_get_code
      .iter()
      .filter_map(pick!(&(_, Insn::Bl { target }) => target))
      .collect();

   let rts_len = u64::try_from(RICH_TEXT_STATE.len()).unwrap_or(0);
   let mut sv_hits = Vec::new();
   for &func in &set_c {
      let Some((_, code)) = arm64::function(image, func) else {
         continue;
      };
      let fn_calls: Vec<(usize, usize)> = code
         .iter()
         .enumerate()
         .filter_map(|(i, &(_, insn))| pick!(in insn, Insn::Bl { target } => (i, target)))
         .collect();
      if fn_calls.len() < 4
         || fn_calls[0].1 == entity_map_get
         || fn_calls[1].1 != text_get
         || !text_get_callees.contains(&fn_calls[0].1)
      {
         continue;
      }
      let takes_cx_in_x4 = code.iter().take(10).any(|&(_, i)| {
         matches!(
            i,
            Insn::MovReg {
               rm: 4,
               wide: true,
               ..
            }
         )
      });
      if !takes_cx_in_x4 {
         continue;
      }
      let none_slots = sorted(
         code
            .windows(2)
            .filter_map(|pair| {
               match (pair[0].1, pair[1].1) {
                  (
                     Insn::MovZ {
                        rd,
                        imm: 0xFF,
                        wide: false,
                     },
                     Insn::Store {
                        rt,
                        rn: 19,
                        offset,
                        size: 1,
                     },
                  ) if rd == rt => Some(offset),
                  _ => None,
               }
            })
            .collect(),
      );
      if none_slots.len() != 1 {
         continue;
      }
      let arc_drop = code.windows(4).find_map(|w| {
         if w[0].1 != Insn::Other(0xD503_39BF) {
            return None;
         }
         w[1..].iter().find_map(pick!(&(_, Insn::Bl { target }) => target))
      });
      let update_dyn = code.windows(2).find_map(|pair| {
         match (pair[0].1, pair[1].1) {
            (
               Insn::MovZ {
                  rd: 3,
                  imm,
                  wide: false,
               },
               Insn::Bl { target },
            ) if imm == rts_len => Some(target),
            _ => None,
         }
      });
      if let (Some(arc_drop_slow), Some(update_entity_dyn)) = (arc_drop, update_dyn) {
         sv_hits.push((func, none_slots[0], arc_drop_slow, update_entity_dyn));
      }
   }
   let (set_value, pending_value, arc_drop_slow, update_entity_dyn) =
      one("FieldState::set_value", &sv_hits)?;

   if !field_slots.contains(&pending_value) {
      return Err("FieldState::new slots do not contain pending_value".to_owned());
   }
   let placeholders: Vec<usize> = field_slots
      .into_iter()
      .filter(|&slot| slot != pending_value)
      .collect();
   let [first, second] = placeholders[..] else {
      return Err("FieldState placeholder slots did not decode".to_owned());
   };

   let (text_input_into_any, text_input_size) = arm64_into_any(image, TEXT_INPUT_TYPE)?;
   let (text_area_into_any, text_area_size) = arm64_into_any(image, TEXT_AREA_TYPE)?;

   let mut hosted = Vec::new();
   for (site, _) in refs_to(image, &[entity_clone]) {
      let Some((func, code)) = arm64::function(image, site) else {
         continue;
      };
      if site - func > 0x20 || code.len() > 80 {
         continue;
      }
      let Some(at) = code.iter().position(|&(pc, _)| pc == site) else {
         continue;
      };
      let sret_reg = code[..at]
         .iter()
         .find_map(pick!(
            &(_, Insn::MovReg { rd, rm: 8, wide: true }) if (19..=28).contains(&rd) => rd
         ))
         .unwrap_or(19);
      let entity = code[at.saturating_sub(3)..at]
         .iter()
         .rev()
         .find_map(pick!(&(_, Insn::AddImm { rd: 8, rn: 8, imm }) => imm));
      let Some(entity) = entity else {
         continue;
      };
      let extent = code
         .iter()
         .filter_map(pick!(
            &(_, Insn::Store { rn, offset, size, .. }) if rn == sret_reg && offset < 0x800 => offset + size
         ))
         .max();
      if let Some(extent) = extent {
         hosted.push((func, entity, extent));
      }
   }
   let hosted_new = |size: usize, name: &str| -> Found<(usize, usize)> {
      let hits = sorted(
         hosted
            .iter()
            .filter(|&&(_, entity, extent)| {
               extent <= size && size - extent < 8 && entity + 0x20 <= size
            })
            .map(|&(func, entity, _)| (func, entity))
            .collect(),
      );
      one(name, &hits)
   };
   let (text_input_new, text_input_entity) = hosted_new(text_input_size, "hosted TextInput::new")?;
   let (text_area_new, text_area_entity) = hosted_new(text_area_size, "hosted TextArea::new")?;

   let text_area_rows = arm64::function(image, text_area_new).and_then(|(_, code)| {
      let zeroed: std::collections::HashSet<usize> = code
         .iter()
         .filter_map(pick!(
            &(_, Insn::Store { rt: 31, rn: 19, offset, size: 1 }) => offset
         ))
         .collect();
      let pairs: Vec<usize> = zeroed
         .iter()
         .copied()
         .filter(|&rows| zeroed.contains(&(rows + 2)) && rows + 4 <= text_area_size)
         .collect();
      match pairs[..] {
         [rows] => Some(rows),
         _ => None,
      }
   });

   Ok(crate::desktop::TextFields {
      cx_new_single,
      cx_new_multiline,
      entity_map_get,
      entity_downgrade,
      weak_drop,
      text_get,
      set_value,
      update_entity_dyn,
      arc_drop_slow,
      text_input_new,
      text_input_into_any,
      text_area_new,
      text_area_into_any,
      layout: crate::desktop::FieldLayout {
         text_input_size,
         text_input_entity,
         text_area_size,
         text_area_entity,
         text_area_rows,
         placeholders: [first, second],
         pending_value,
         app_entities,
         weak_ptr,
      },
   })
}

fn arm64_field_state_new(image: &Image<'_>) -> Found<(usize, usize, usize, [usize; 3])> {
   const SINGLE_PREFIX: [u8; 16] = [
      0xE3, 0x03, 0x01, 0xAA, // mov x3, x1
      0xE2, 0x03, 0x00, 0xAA, // mov x2, x0
      0xE0, 0x03, 0x08, 0xAA, // mov x0, x8
      0x01, 0x00, 0x80, 0x52, // mov w1, #0
   ];
   const MULTI_PREFIX: [u8; 16] = [
      0xE3, 0x03, 0x01, 0xAA, // mov x3, x1
      0xE2, 0x03, 0x00, 0xAA, // mov x2, x0
      0xE0, 0x03, 0x08, 0xAA, // mov x0, x8
      0x21, 0x00, 0x80, 0x52, // mov w1, #1
   ];
   let tail_target = |at: usize| -> Option<usize> {
      if !image.is_function(at) {
         return None;
      }
      let word = image.read_u32(at + 16)?;
      match arm64::decode(word, at + 16) {
         Insn::B { target } => Some(target),
         _ => None,
      }
   };
   let multis: HashMap<usize, usize> = image
      .find_bytes(&MULTI_PREFIX)
      .into_iter()
      .filter_map(|at| Some((tail_target(at)?, at)))
      .collect();

   let mut pairs = Vec::new();
   for single in image.find_bytes(&SINGLE_PREFIX) {
      let Some(inner) = tail_target(single) else {
         continue;
      };
      let Some(&multi) = multis.get(&inner) else {
         continue;
      };
      let Some((_, code)) = arm64::function(image, inner) else {
         continue;
      };
      let ret = code
         .iter()
         .position(|&(_, insn)| insn == Insn::Ret)
         .unwrap_or(code.len());
      let slots = code[..ret].windows(4).rev().find_map(|w| {
         match (w[0].1, w[1].1, w[2].1, w[3].1) {
            (
               Insn::MovZ {
                  rd,
                  imm: 0xFF,
                  wide: false,
               },
               Insn::Store {
                  rt: t1,
                  rn: b1,
                  offset: o1,
                  size: 1,
               },
               Insn::Store {
                  rt: t2,
                  rn: b2,
                  offset: o2,
                  size: 1,
               },
               Insn::Store {
                  rt: t3,
                  rn: b3,
                  offset: o3,
                  size: 1,
               },
            ) if t1 == rd && t2 == rd && t3 == rd && b1 == b2 && b2 == b3 => Some([o1, o2, o3]),
            _ => None,
         }
      });
      if let Some(slots) = slots {
         pairs.push((single, multi, inner, slots));
      }
   }
   one("FieldState::new thunks", &pairs)
}

fn arm64_pick_cx_new(
   image: &Image<'_>,
   ctor: usize,
   inner: usize,
   name: &str,
) -> Found<(usize, usize, usize, usize)> {
   let has_app_bump = |insns: &[(usize, Insn)]| {
      insns.windows(3).any(|w| {
         matches!(
            (w[0].1, w[1].1, w[2].1),
            (
               Insn::Load {
                  rt: 8,
                  rn: 0,
                  offset: o1,
                  size: 8,
               },
               Insn::AddImm {
                  rd: 8,
                  rn: 8,
                  imm: 1,
               },
               Insn::Store {
                  rt: 8,
                  rn: 0,
                  offset: o2,
                  size: 8,
               },
            ) if o1 == o2 && o1 >= 0x100
         )
      })
   };

   let mut matches = Vec::new();
   for func in loaders(image, &[ctor]) {
      let Some((start, end)) = image.function_bounds(func) else {
         continue;
      };
      if end - start > 0x160 {
         continue;
      }
      let flat = flattened_at(image, func);
      let head_len = flat.len().min(24);
      let bumps_app = has_app_bump(&flat[..head_len])
         || flat[..head_len]
            .iter()
            .find_map(pick!(&(_, Insn::Bl { target }) => arm64::function(image, target).map(|(_, body)| body)?))
            .is_some_and(|body| body.len() <= 12 && has_app_bump(&body));
      if !bumps_app {
         continue;
      }
      let fn_calls: Vec<usize> = flat
         .iter()
         .filter_map(pick!(&(_, Insn::Bl { target } | Insn::B { target }) => target))
         .collect();
      let Some(pos) = fn_calls.iter().position(|&c| c == ctor || c == inner) else {
         continue;
      };
      if pos < 4 || pos + 1 >= fn_calls.len() {
         continue;
      }
      let entity_clone = fn_calls[pos - 3];
      let entity_downgrade = fn_calls[pos - 1];
      let weak_drop = fn_calls[pos + 1];
      let down_ok = arm64::function(image, entity_downgrade).is_some_and(|(_, body)| {
         body.len() <= 20
            && body
               .iter()
               .any(|&(_, i)| matches!(i, Insn::Other(w) if w & 0xFFFF_FC1F == 0xB100_041F))
      });
      let weak_ok = flat.windows(3).any(|w| {
         matches!(
            (w[0].1, w[1].1, w[2].1),
            (
               Insn::MovZ { imm: 1, .. },
               Insn::AddImm {
                  rd: 0,
                  imm: 0x10,
                  ..
               },
               Insn::Bl { target } | Insn::B { target },
            ) if target == weak_drop
         )
      });
      if down_ok && weak_ok {
         matches.push((func, entity_clone, entity_downgrade, weak_drop));
      }
   }
   matches.sort_by_key(|&(func, ..)| func);
   matches
      .into_iter()
      .next()
      .ok_or_else(|| format!("{name} not found"))
}

/// GPUI's per-view next-frame scheduler, `fn(window: *mut c_void, app: *mut
/// c_void)`.
pub fn animation_frame(image: &Image<'_>) -> Found<usize> {
   let scrim = one("modal-layer-scrim", &image.find_bytes(b"modal-layer-scrim"))?;
   let mut roots = Vec::new();
   for (site, _) in refs_to(image, &[scrim]) {
      let Some((_, body)) = arm64::function(image, site) else {
         continue;
      };
      let Some(at) = body.iter().position(|&(pc, _)| pc == site) else {
         continue;
      };
      for &(_, insn) in body[at + 1..].iter().take(28) {
         if let Insn::Bl { target } = insn
            && image.is_function(target)
         {
            roots.push(target);
         }
      }
   }
   let func_targets = |func: usize| -> Vec<usize> {
      let Some((_, body)) = arm64::function(image, func) else {
         return Vec::new();
      };
      sorted(
         body
            .iter()
            .filter_map(|&(_, insn)| {
               match insn {
                  Insn::Bl { target } | Insn::B { target } if image.is_function(target) => {
                     Some(target)
                  },
                  _ => None,
               }
            })
            .collect(),
      )
   };
   let is_notify = |func: usize| -> bool {
      let Some((_, body)) = arm64::function(image, func) else {
         return false;
      };
      (32..=128).contains(&body.len())
         && body.iter().any(|&(_, insn)| matches!(insn, Insn::Blr { .. }))
         && allocs(&flattened(image, func)).any(|(_, size, align, _)| size == 12 && align == 4)
   };
   let callers_of = |notify_fn: usize| {
      sorted(
         refs_to(image, &[notify_fn])
            .into_iter()
            .filter_map(|(site, _)| image.function_containing(site))
            .collect(),
      )
   };

   crate::desktop::find_animation_frame(sorted(roots), func_targets, is_notify, callers_of, |f| {
      arm64::function(image, f).is_some_and(|(_, body)| body.len() <= 64)
   })
}

/// Decodes `ScaleFade`'s byte size from the `[x0 + off]` copies in
/// `ScaleFade::into_any_element`.
fn arm64_scale_fade_size(image: &Image<'_>, into_any: usize) -> Found<usize> {
   let (_, body) = arm64::function(image, into_any).ok_or("ScaleFade::into_any did not decode")?;
   let mut max_end = 0usize;
   for &(_, insn) in &body {
      match insn {
         Insn::Load {
            rn: 0,
            offset,
            size,
            ..
         } => max_end = max_end.max(offset + size),
         Insn::Other(w) if w & 0xFFC0_03E0 == 0xAD40_0000 => {
            let imm7 = ((w >> 15) & 0x7F) as usize;
            if imm7 & 0x40 == 0 {
               max_end = max_end.max(imm7 * 16 + 32);
            }
         },
         Insn::Other(w) if w & 0xFFC0_03E0 == 0x3DC0_0000 => {
            let imm12 = ((w >> 10) & 0xFFF) as usize;
            max_end = max_end.max(imm12 * 16 + 16);
         },
         _ => {},
      }
   }
   if max_end == 0 {
      max_end = body
         .windows(2)
         .find_map(|pair| {
            match (pair[0].1, pair[1].1) {
               (
                  Insn::MovZ {
                     rd: 2,
                     imm,
                     wide: false,
                  },
                  Insn::Bl { .. },
               ) => usize::try_from(imm).ok(),
               _ => None,
            }
         })
         .unwrap_or(0);
   }
   if max_end == 0 {
      return Err("ScaleFade size not found in into_any".to_owned());
   }
   Ok(max_end)
}

/// Discord's `mana_gpui::components::motion::effects::ScaleFade::into_any_element`
/// and its decoded struct layout from `mana_modal_layer`.
#[expect(
   clippy::too_many_lines,
   reason = "decodes all ScaleFade and ElementId field offsets from mana_modal_layer"
)]
pub fn scale_fade(image: &Image<'_>) -> Found<crate::desktop::ScaleFade> {
   const MODAL_SCALE: &[u8] = b"modal-scale";
   let anchor = one("modal-scale", &image.find_bytes(MODAL_SCALE))?;
   let mut parents = Vec::new();
   for (site, _) in refs_to(image, &[anchor]) {
      if let Some(func) = image.function_containing(site) {
         parents.push(func);
      }
   }
   let parent = one("mana_modal_layer", &sorted(parents))?;
   let (_, body) = arm64::function(image, parent).ok_or("mana_modal_layer did not decode")?;
   let callees = sorted(
      body
         .iter()
         .filter_map(|&(_, insn)| match insn {
            Insn::Bl { target } if image.is_function(target) => Some(target),
            _ => None,
         })
         .collect(),
   );

   let type_names = image.find_bytes(b"mana_gpui::components::motion::effects::ScaleFade");
   let type_users: std::collections::HashSet<usize> = refs_to(image, &type_names)
      .into_iter()
      .filter_map(|(site, _)| image.function_containing(site))
      .collect();
   let candidates: Vec<usize> = callees
      .into_iter()
      .filter(|callee| type_users.contains(callee))
      .collect();
   let into_any = one("scale_fade", &candidates)?;
   let size = arm64_scale_fade_size(image, into_any)?;

   let loads = loaded(&body);
   let (anchor_at, call_at) = body
      .iter()
      .enumerate()
      .filter(|&(_, &(_, insn))| insn == Insn::Bl { target: into_any })
      .find_map(|(call_at, _)| {
         let start = call_at.saturating_sub(48);
         let anchor_at = (start..call_at)
            .rev()
            .find(|&idx| loads[idx].is_some_and(|(_, addr)| addr == anchor))?;
         Some((anchor_at, call_at))
      })
      .ok_or("ScaleFade call after modal-scale not found")?;

   let base = body[call_at.saturating_sub(8)..call_at]
      .iter()
      .rev()
      .find_map(pick!(&(_, Insn::AddImm { rd: 0, rn: 31, imm }) => imm))
      .ok_or("ScaleFade stack base (x0) not found")?;
   let caller_loc = loads[call_at.saturating_sub(8)..call_at]
      .iter()
      .rev()
      .find_map(|load| load.and_then(pick!((1, addr) => addr)))
      .ok_or("ScaleFade caller_loc (x1) not found")?;

   let mut clamped_fp = [false; 32];
   for &(_, insn) in &body[..call_at] {
      // `fcmp sN, #0.0` clamps `progress` for the modal scrim.
      if let Insn::Other(w) = insn
         && w & 0xFFFF_FC1F == 0x1E20_2008
      {
         clamped_fp[((w >> 5) & 0x1F) as usize] = true;
      }
   }

   let win_start = anchor_at.saturating_sub(6);
   let mut imm_val: [Option<u64>; 32] = [None; 32];
   let mut adrp_page: [Option<usize>; 32] = [None; 32];
   let mut ptr_reg: [Option<usize>; 32] = [None; 32];
   let mut q_src: [Option<usize>; 32] = [None; 32];
   let mut d_opacity = [false; 32];
   let mut pending_sret: Option<usize> = None;
   let mut child_tmp: Option<usize> = None;
   let mut ptr_slot: Option<usize> = None;
   let mut byte_imm_stores: Vec<(usize, u8)> = Vec::new();
   let mut qword_stores: Vec<(usize, Option<u64>)> = Vec::new();
   let mut vec_copies: Vec<(usize, usize)> = Vec::new();
   let mut opacity_range: Option<usize> = None;
   let mut fp_stores: Vec<(u8, usize)> = Vec::new();
   let mut origin: Option<usize> = None;

   for &(_, insn) in &body[win_start..call_at] {
      match insn {
         Insn::Adrp { rd, page } => {
            let r = usize::from(rd);
            adrp_page[r] = Some(page);
            imm_val[r] = None;
            ptr_reg[r] = None;
         },
         Insn::AddImm { rd, rn, imm } => {
            let r = usize::from(rd);
            if rd == 8 && rn == 31 {
               pending_sret = Some(imm);
            }
            ptr_reg[r] = adrp_page[usize::from(rn)].map(|page| page.wrapping_add(imm));
            adrp_page[r] = None;
            imm_val[r] = None;
         },
         Insn::MovZ { rd, imm, .. } => {
            let r = usize::from(rd);
            imm_val[r] = Some(imm);
            adrp_page[r] = None;
            ptr_reg[r] = None;
         },
         Insn::MovN { rd, imm, .. } => {
            let r = usize::from(rd);
            imm_val[r] = Some(!imm);
            adrp_page[r] = None;
            ptr_reg[r] = None;
         },
         Insn::MovReg { rd, rm, .. } => {
            let (d, s) = (usize::from(rd), usize::from(rm));
            imm_val[d] = imm_val[s];
            adrp_page[d] = adrp_page[s];
            ptr_reg[d] = ptr_reg[s];
         },
         Insn::Load { rt, .. } => {
            let r = usize::from(rt);
            imm_val[r] = None;
            adrp_page[r] = None;
            ptr_reg[r] = None;
         },
         Insn::Store {
            rt,
            rn: 31,
            offset,
            size: store_size,
         } => {
            let r = usize::from(rt);
            match store_size {
               1 => {
                  if let Some(v) = imm_val[r].and_then(|v| u8::try_from(v).ok()) {
                     byte_imm_stores.push((offset, v));
                  }
               },
               4 => {
                  if rt == 31 && (base..base + size).contains(&offset) {
                     origin = Some(offset - base);
                  }
               },
               8 => {
                  if ptr_reg[r] == Some(anchor) {
                     ptr_slot = Some(offset);
                  }
                  qword_stores.push((offset, imm_val[r]));
               },
               _ => {},
            }
         },
         Insn::Bl { .. } => {
            if let Some(slot) = pending_sret.take() {
               child_tmp = Some(slot);
            }
            for r in 0..19 {
               imm_val[r] = None;
               adrp_page[r] = None;
               ptr_reg[r] = None;
            }
         },
         Insn::Other(w) => {
            // `ldr qT, [sp, #imm12*16]`
            if w & 0xFFC0_03E0 == 0x3DC0_03E0 {
               let rt = (w & 0x1F) as usize;
               let off = (((w >> 10) & 0xFFF) as usize) * 16;
               q_src[rt] = Some(off);
            // `stp qA, qB, [sp, #imm7*16]`
            } else if w & 0xFFC0_03E0 == 0xAD00_03E0 {
               let rt1 = (w & 0x1F) as usize;
               let imm7 = ((w >> 15) & 0x7F) as usize;
               if imm7 & 0x40 == 0
                  && let Some(src) = q_src[rt1]
               {
                  vec_copies.push((src, imm7 * 16));
               }
            // `str qT, [sp, #imm12*16]`
            } else if w & 0xFFC0_03E0 == 0x3D80_03E0 {
               let rt = (w & 0x1F) as usize;
               let dst = (((w >> 10) & 0xFFF) as usize) * 16;
               if let Some(src) = q_src[rt] {
                  vec_copies.push((src, dst));
               }
            // `ldr dT, [xN, #imm12*8]`
            } else if w & 0xFFC0_0000 == 0xFD40_0000 {
               let rt = (w & 0x1F) as usize;
               let rn = ((w >> 5) & 0x1F) as usize;
               let off = (((w >> 10) & 0xFFF) as usize) * 8;
               d_opacity[rt] = adrp_page[rn]
                  .and_then(|page| image.read(page.wrapping_add(off), 8))
                  .is_some_and(|b| {
                     u32::from_le_bytes([b[0], b[1], b[2], b[3]]) == 0.0f32.to_bits()
                        && u32::from_le_bytes([b[4], b[5], b[6], b[7]]) == 1.0f32.to_bits()
                  });
            // `str dT, [sp, #imm12*8]`
            } else if w & 0xFFC0_03E0 == 0xFD00_03E0 {
               let rt = (w & 0x1F) as usize;
               let dst = (((w >> 10) & 0xFFF) as usize) * 8;
               if d_opacity[rt] && (base..base + size).contains(&dst) {
                  opacity_range = Some(dst - base);
               }
            // `str sT, [sp, #imm12*4]`
            } else if w & 0xFFC0_03E0 == 0xBD00_03E0 {
               let rt = (w & 0x1F) as u8;
               let dst = (((w >> 10) & 0xFFF) as usize) * 4;
               if (base..base + size).contains(&dst) {
                  fp_stores.push((rt, dst - base));
               }
            } else {
               let rd = (w & 0x1F) as usize;
               imm_val[rd] = None;
               adrp_page[rd] = None;
               ptr_reg[rd] = None;
            }
         },
         _ => {},
      }
   }

   let ptr_slot = ptr_slot.ok_or("modal-scale ptr slot not found")?;
   let ss_slot = ptr_slot
      .checked_sub(8)
      .ok_or("modal-scale SharedString slot underflow")?;
   if !byte_imm_stores.contains(&(ss_slot, 0x18))
      || !qword_stores.contains(&(ptr_slot + 8, Some(MODAL_SCALE.len() as u64)))
   {
      return Err("modal-scale SharedString shape changed".to_owned());
   }
   let (id_tmp, element_id) = vec_copies
      .iter()
      .find_map(|&(src, dst)| {
         (src <= ss_slot && ss_slot < src + 32 && (base..base + size).contains(&dst))
            .then_some((src, dst - base))
      })
      .ok_or("ScaleFade element_id copy not found")?;
   let element_id_str = ss_slot - id_tmp;
   let (element_id_tag_off, element_id_tag) = byte_imm_stores
      .iter()
      .find_map(|&(slot, val)| {
         ((id_tmp..id_tmp + 0x28).contains(&slot) && slot != ss_slot)
            .then_some((slot - id_tmp, val))
      })
      .ok_or("ScaleFade ElementId tag not found")?;
   let element_id_key = qword_stores
      .iter()
      .find_map(|&(slot, _)| {
         ((id_tmp..id_tmp + 0x28).contains(&slot) && slot != ptr_slot && slot != ptr_slot + 8)
            .then_some(slot - id_tmp)
      })
      .ok_or("ScaleFade ElementId key slot not found")?;

   let child_tmp = child_tmp.ok_or("ScaleFade child sret slot not found")?;
   let child = vec_copies
      .iter()
      .find_map(|&(src, dst)| {
         (src == child_tmp && (base..base + size).contains(&dst)).then_some(dst - base)
      })
      .ok_or("ScaleFade child copy not found")?;
   let opacity_range = opacity_range.ok_or("ScaleFade opacity_range not found")?;
   let label_none = byte_imm_stores
      .iter()
      .find_map(|&(dst, val)| {
         (val == 0xFF && (base..base + size).contains(&dst)).then_some(dst - base)
      })
      .ok_or("ScaleFade label_none not found")?;
   let fade = byte_imm_stores
      .iter()
      .find_map(|&(dst, val)| {
         (val == 1 && (base..base + size).contains(&dst)).then_some(dst - base)
      })
      .ok_or("ScaleFade fade flag not found")?;
   let origin = origin.ok_or("ScaleFade origin not found")?;

   let [(r0, o0), (r1, o1)] = fp_stores.as_slice() else {
      return Err(format!(
         "ScaleFade expected 2 float stores, got {}",
         fp_stores.len()
      ));
   };
   let (progress, scale_from) = match (
      clamped_fp[usize::from(*r0)],
      clamped_fp[usize::from(*r1)],
   ) {
      (true, false) => (*o0, *o1),
      (false, true) => (*o1, *o0),
      _ => return Err("ScaleFade progress/scale_from ambiguous".to_owned()),
   };

   let layout = crate::desktop::validate_scale_fade_layout(crate::desktop::ScaleFadeLayout {
      size,
      child,
      opacity_range,
      label_none,
      element_id,
      element_id_tag_off,
      element_id_tag,
      element_id_key,
      element_id_str,
      progress,
      scale_from,
      origin,
      fade,
   })?;
   Ok(crate::desktop::ScaleFade {
      into_any,
      caller_loc,
      layout,
   })
}

#[cfg(test)]
mod tests {
   use super::*;

   fn decode_words(words: &[u32]) -> Vec<Insn> {
      words
         .iter()
         .enumerate()
         .map(|(i, &w)| arm64::decode(w, 0x1000 + i * 4))
         .collect()
   }

   // Build 2233 ReqwestTransport::send request call, header copy, and body tag dispatch.
   const SEND_2233: &[u32] = &[
      0xAA01_03F3, // mov x19, x1
      0x9123_C3FC, // add x28, sp, #0x8f0
      0x3CCF_8260, // ldur q0, [x19, #0xf8]
      0xF940_8668, // ldr x8, [x19, #0x108]
      0xF904_83E8, // str x8, [sp, #0x900]
      0x3D80_0380, // str q0, [x28]
      0x9123_C3E1, // add x1, sp, #0x8f0
      0x9102_C262, // add x2, x19, #0xb0
      0x9400_0010, // bl Client::request
      0x9123_C3E0, // add x0, sp, #0x8f0
      0xAA13_03E1, // mov x1, x19
      0x5280_0C02, // mov w2, #0x60
      0x9400_0020, // bl memcpy
      0xAA13_03F6, // mov x22, x19
      0xF847_8EC8, // ldr x8, [x22, #0x78]!
      0x3868_692B, // ldrb w11, [x9, x8]
      0x8B0B_094A, // add x10, x10, x11, lsl #2
      0xD61F_0140, // br x10
   ];

   #[test]
   fn rejects_overlapping_arm64_request_fields() {
      let mut words = SEND_2233.to_vec();
      // Point body tag inside the header map (0x58 instead of 0x78).
      words[14] = 0xF845_8EC8;
      assert!(request_layout_in(&decode_words(&words)).is_err());
   }
}
