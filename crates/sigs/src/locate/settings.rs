//! Desktop settings page 24, which the runtime turns into Sunbird's page, and
//! the client's optimistic message delete.

use std::collections::HashMap;

use crate::{
   Found,
   index::{
      Func,
      Index,
      Isa,
      Native,
      Op,
      Reg,
      Step,
   },
   one,
   registry::GatewayRegistry,
};

/// Page 24's sidebar name `Phoenix` and its id, both relabeled in place.
#[derive(Clone, Copy, Debug)]
pub struct SettingsLabel {
   pub name:   usize,
   /// The id literal the code loads, `DESKTOP_PHOENIX` or `PHOENIX`.
   pub id:     usize,
   /// The `PHOENIX` that ends the id.
   pub suffix: usize,
}

/// The function that loads both an id ending in `PHOENIX` and a `Phoenix`
/// name.
///
/// COFF and Mach-O builds pack them as `PhoenixDESKTOP_PHOENIX`, ELF
/// builds place them apart, and Linux builds after 2233 drop `DESKTOP_`.
pub fn settings_label(ix: &Index<'_>) -> Found<SettingsLabel> {
   const NAME: &[u8] = b"Phoenix";
   const ID: &[u8] = b"PHOENIX";
   const PREFIX: &[u8] = b"DESKTOP_";

   let mut found = Vec::new();
   for suffix in ix.text(ID) {
      let prefixed = suffix
         .checked_sub(PREFIX.len())
         .filter(|&start| ix.image.read(start, PREFIX.len()) == Some(PREFIX));
      for id in prefixed.into_iter().chain([suffix]) {
         for func in ix.loaders(id..id + 1) {
            let names = func
               .loads()
               .into_iter()
               .filter(|&name| ix.image.read(name, NAME.len()) == Some(NAME));
            found.extend(names.map(|name| (name, id, suffix)));
         }
      }
   }
   found.sort_unstable();
   found.dedup();
   let (name, id, suffix) = one("settings label loader", &found)?;
   Ok(SettingsLabel { name, id, suffix })
}

/// A `cmp page - 9, 15` that sends pages outside 9 to 24 to "visible".
#[derive(Clone, Copy, Debug)]
pub struct VisibilityGuard {
   pub cmp: usize,
   pub len: u8,
}

impl VisibilityGuard {
   /// The x86-64 `cmp r32, imm8` immediate byte.
   #[must_use]
   pub const fn imm8(&self) -> usize {
      self.cmp + self.len as usize - 1
   }
}

/// Every copy of `is_page_visible`'s page-range guard, which the runtime
/// lowers so page 24 is always shown.
///
/// Pages 9 to 24 switch on flags through a jump table and the rest are
/// visible, so each copy opens with `page - 9`, a compare with 15, a branch,
/// and soon after the table's address.
pub fn settings_visibility(ix: &Index<'_>) -> Found<Vec<VisibilityGuard>> {
   const HEAD: usize = 12;
   const OPENS: usize = 4;
   const TABLE: usize = 8;

   let guard = |head: &[Step]| {
      (1..OPENS.min(head.len().saturating_sub(1))).find_map(|at| {
         let Op::Cmp { reg, value: 15 } = head[at].op else {
            return None;
         };
         let table = head[at + 2..head.len().min(at + 2 + TABLE)]
            .iter()
            .any(|step| matches!(step.op, Op::Addr { .. }));
         (matches!(head[at + 1].op, Op::Branch(_))
            && table
            && subtracts(ix, &head[at - 1]) == Some((reg, 9)))
         .then_some(VisibilityGuard {
            cmp: head[at].at,
            len: head[at].len,
         })
      })
   };
   let found = ix
      .heads(HEAD, |head| guard(head).is_some())
      .into_iter()
      .filter_map(|func| guard(&func.steps()))
      .collect::<Vec<_>>();
   match found.len() {
      1..=4 => Ok(found),
      count => Err(format!("settings visibility guard matched {count} times")),
   }
}

/// `(dst, imm)` for `dst = src - imm` in 32 bits: `lea r32, [r - imm]` or
/// `sub w, w, #imm`.
fn subtracts(ix: &Index<'_>, step: &Step) -> Option<(Reg, u64)> {
   match step.native {
      #[cfg(any(target_arch = "x86_64", target_os = "macos"))]
      Native::X86(iced_x86::Mnemonic::Lea) => {
         let code = ix.image.read(step.at, usize::from(step.len))?;
         let insn = iced_x86::Decoder::with_ip(64, code, step.at as u64, 0).decode();
         let dst = insn.op0_register();
         let disp = insn.memory_displacement64().cast_signed();
         if !dst.is_gpr32() || insn.memory_index() != iced_x86::Register::None || disp >= 0 {
            return None;
         }
         Some((
            Reg::try_from(dst.full_register().number()).ok()?,
            disp.unsigned_abs(),
         ))
      },
      Native::Arm64(phoenix_hook::arm64::Insn::Other(word))
         if word & 0xFFC0_0000 == 0x5100_0000 =>
      {
         Some(((word & 0x1F) as Reg, u64::from((word >> 10) & 0xFFF)))
      },
      _ => None,
   }
}

/// `host::section`, which renders a settings page, and the offset of the
/// active page byte in the state it renders.
#[derive(Clone, Copy, Debug)]
pub struct Section {
   pub func:        usize,
   pub page_offset: usize,
}

/// The one function that loads `account-loading`, and its first byte read
/// off `self` or a copy of it at an offset a page byte sits at.
pub fn settings_section(ix: &Index<'_>) -> Found<Section> {
   const HEAD: usize = 96;

   let func = ix.literal(b"account-loading").one("account-loading load")?;
   // The hidden return pointer takes the first argument register on x86-64
   // and x8 on arm64, so `self` arrives second or first.
   let this = match ix.isa {
      #[cfg(any(target_arch = "x86_64", target_os = "macos"))]
      Isa::X86_64 { .. } => ix.isa.arg(1),
      Isa::Aarch64 | Isa::Thumb2 => ix.isa.arg(0),
   }
   .ok_or("no self register")?;
   let mut copies = vec![this];
   let page_offset = func
      .steps()
      .iter()
      .take(HEAD)
      .find_map(|step| {
         match step.op {
            Op::Move { dst, src } if copies.contains(&src) => copies.push(dst),
            Op::Load {
               base,
               offset,
               size: 1,
               ..
            } if copies.contains(&base) && (0x100..0x2000).contains(&offset) => {
               return usize::try_from(offset).ok();
            },
            _ => {},
         }
         None
      })
      .ok_or("settings section active page load not found")?;
   Ok(Section {
      func: func.start,
      page_offset,
   })
}

/// The client's own message deletes, found from the `MESSAGE_DELETE` handler.
#[derive(Clone, Debug)]
pub struct OptimisticDelete {
   /// The one other caller of callees only the handler and it call.
   pub sibling: usize,
   /// `Store::delete_message`, which the message menu runs, and its copies
   /// for other message maps, sorted.
   pub deletes: Vec<usize>,
}

/// `Store::delete_message` and its sibling, from the `MESSAGE_DELETE` handler.
///
/// A sibling shares at least 4 callees with the handler, one of them called
/// by nothing else. The delete takes the sibling's lock, its first call, and
/// then removes through the handler's map delete, the shared callee with the
/// fewest callers beyond two, right after the call the sibling makes before
/// it. Other siblings exist, and only the store's has such a delete. A copy
/// makes the same calls but one, its map's removal (every build seen has one).
pub fn optimistic_delete<'ix>(ix: &'ix Index<'ix>, handler: Func<'ix>) -> Found<OptimisticDelete> {
   const SHARED: usize = 4;
   // The map deletes have under 10 call sites on every build seen, allocators
   // and drops hundreds of thousands, whose caller sets cost 110 ms on macOS.
   const MANY: usize = 64;

   let mut shared = handler.calls();
   shared.sort_unstable();
   shared.dedup();
   let parents = shared
      .iter()
      .filter(|&&callee| ix.call_sites(callee).len() <= MANY)
      .filter_map(|&callee| Some((callee, ix.func(callee).ok()?.callers())))
      .collect::<HashMap<_, _>>();
   let mut siblings = parents
      .values()
      .filter(|callers| {
         callers.len() == 2 && callers.iter().any(|func| func.start == handler.start)
      })
      .flat_map(|callers| {
         callers
            .iter()
            .map(|func| func.start)
            .filter(|&start| start != handler.start)
      })
      .collect::<Vec<_>>();
   siblings.sort_unstable();
   siblings.dedup();

   let delete_beside = |sibling: Func<'ix>| -> Option<Vec<usize>> {
      let calls = sibling.calls();
      let overlap = shared
         .iter()
         .filter(|callee| calls.contains(callee))
         .count();
      if overlap < SHARED {
         return None;
      }
      let lock = *calls.first()?;
      let (remove, callers) = calls
         .iter()
         .filter_map(|callee| Some((*callee, parents.get(callee)?)))
         .filter(|(_, callers)| callers.len() > 2)
         .min_by_key(|(_, callers)| callers.len())?;
      let before_remove = |calls: &[usize]| {
         let until = calls.iter().position(|&callee| callee == remove)?;
         calls[..until].last().copied()
      };
      let last = before_remove(&calls)?;
      let deletes = callers
         .iter()
         .filter(|func| func.start != handler.start && func.start != sibling.start)
         .filter(|func| {
            let calls = func.calls();
            calls.first() == Some(&lock) && before_remove(&calls) == Some(last)
         })
         .map(|func| func.start)
         .collect::<Vec<_>>();
      (!deletes.is_empty()).then_some(deletes)
   };
   let found = siblings
      .iter()
      .filter_map(|&start| {
         let sibling = ix.func(start).ok()?;
         Some((start, delete_beside(sibling)?))
      })
      .collect::<Vec<_>>();
   let (sibling, deletes) = match found.as_slice() {
      [(sibling, deletes)] => (*sibling, deletes),
      _ => {
         return Err(format!(
            "optimistic delete sibling matched {} times",
            found.len()
         ));
      },
   };
   let delete = ix.func(one("optimistic delete", deletes)?)?;
   let calls = delete.calls();
   let anchor = calls
      .iter()
      .min_by_key(|&&callee| ix.call_sites(callee).len())
      .ok_or("optimistic delete calls nothing")?;
   let mut deletes = ix
      .func(*anchor)?
      .callers()
      .iter()
      .filter(|func| {
         let copy = func.calls();
         copy.len() == calls.len()
            && copy
               .iter()
               .zip(&calls)
               .filter(|(copied, called)| copied != called)
               .count()
               <= 1
      })
      .map(|func| func.start)
      .collect::<Vec<_>>();
   deletes.sort_unstable();
   deletes.dedup();
   Ok(OptimisticDelete { sibling, deletes })
}

/// [`optimistic_delete`] from the gateway registry's `MESSAGE_DELETE` entry.
pub fn optimistic_delete_of<'ix>(ix: &'ix Index<'ix>) -> Found<OptimisticDelete> {
   let registry = GatewayRegistry::locate(ix.image).map_err(|err| err.to_string())?;
   let id = registry.id("MESSAGE_DELETE").ok_or("no MESSAGE_DELETE")?;
   optimistic_delete(ix, ix.func(registry.entry(id).handler)?)
}
