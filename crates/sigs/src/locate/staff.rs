//! `flag_override: Option<bool>` in the store state, the field the staff hook
//! flips, found from the readers in `ops/experiments.rs`.
//!
//! Those readers take the state's read lock into a guard on the stack, then
//! read the flag's discriminant and payload through it. Of the field pairs
//! they read, the flag is the one every build reads through a guard.
//!
//! Offsets are from what the gateway handler's first argument points at. On
//! x86 that is the state, `LOCK_DATA` past the lock the guard holds. On arm64
//! it is the lock itself, so the guard's offset stands. Windows, macOS and a
//! Pixel (357200) showed the staff settings at these offsets, and macOS shows
//! nothing at the state read it also makes 0x10 lower.

use std::{
   collections::{
      BTreeMap,
      HashMap,
   },
   fmt,
};

use crate::{
   Found,
   StaffField,
   index::{
      Func,
      Index,
      Isa,
      Native,
      Op,
      Reg,
      Value,
   },
};

/// Where std's futex `RwLock<T>` keeps `T`, after its two `u32` atomics and the
/// poison flag.
const LOCK_DATA: isize = 0x10;

/// How many instructions may separate the discriminant read from the payload
/// read.
const PAIR_REACH: usize = 3;

/// A field read through a guard, its offset counted through the adds that
/// moved the guard's pointer, and the call that filled the guard.
#[derive(Clone, Copy)]
struct Read {
   step:   usize,
   base:   Reg,
   offset: isize,
   lock:   usize,
}

/// The 4- and 8-byte reads and in-place compares in `func` whose base is a
/// pointer loaded from a stack slot a call filled.
fn reads(ix: &Index<'_>, func: &Func<'_>) -> Vec<Read> {
   let sp = usize::from(ix.isa.sp());
   let mut bias = [0isize; 32];
   // Which call filled the guard a register's pointer was loaded from.
   let mut guard = [None::<usize>; 32];
   // The stack offset each register points at, and the slots calls filled.
   let mut stack = [None::<isize>; 32];
   let mut filled = HashMap::<isize, usize>::new();
   let mut out = Vec::new();
   stack[sp] = Some(0);
   for (step, at) in func.steps().iter().enumerate() {
      let mut read = |base: Reg, offset: isize, bias: &[isize; 32]| {
         if let Some(lock) = guard[usize::from(base)] {
            out.push(Read {
               step,
               base,
               offset: bias[usize::from(base)] + offset,
               lock,
            });
         }
      };
      match at.op {
         Op::Load {
            reg,
            base,
            offset,
            size,
         } => {
            if size == 4 || size == 8 {
               read(base, offset, &bias);
            }
            let slot = stack[usize::from(base)].map(|at| at + offset);
            let reg = usize::from(reg);
            bias[reg] = 0;
            stack[reg] = None;
            guard[reg] = slot.and_then(|slot| filled.get(&slot).copied());
         },
         Op::CmpMem { base, offset, .. } => read(base, offset, &bias),
         Op::Call(callee) => {
            for (reg, slot) in stack.iter().enumerate() {
               if let Some(slot) = slot
                  && reg != sp
               {
                  filled.insert(*slot, callee);
               }
            }
         },
         Op::Offset { reg, base, offset } => {
            let (reg, base) = (usize::from(reg), usize::from(base));
            bias[reg] = bias[base] + offset;
            guard[reg] = guard[base];
            stack[reg] = stack[base].map(|at| at + offset);
         },
         Op::Move { dst, src } => {
            let (dst, src) = (usize::from(dst), usize::from(src));
            bias[dst] = bias[src];
            guard[dst] = guard[src];
            stack[dst] = stack[src];
         },
         Op::Addr { reg, .. } | Op::Imm { reg, .. } => {
            let reg = usize::from(reg);
            bias[reg] = 0;
            guard[reg] = None;
            stack[reg] = None;
         },
         _ => {},
      }
   }
   out
}

/// Whether the guard `lock` fills points at the lock itself, so reads through
/// it land `LOCK_DATA` past the state's fields: it stores into the guard the
/// register it ran an atomic on.
fn points_at_lock(ix: &Index<'_>, lock: usize) -> bool {
   let Ok(func) = ix.func(lock) else {
      return false;
   };
   let steps = func.steps();
   let atomics = steps
      .iter()
      .filter_map(|step| {
         match step.op {
            Op::Atomic { base, offset: 0 } => Some(base),
            _ => None,
         }
      })
      .collect::<Vec<Reg>>();
   steps.iter().any(|step| {
      matches!(step.op,
         Op::Store { value: Value::Reg(value), offset: 0, size: 8, .. } if atomics.contains(&value))
   })
}

/// The tags of the `(tag, tag + 8)` pairs read off one guard close together,
/// in state offsets.
fn pairs(ix: &Index<'_>, reads: &[Read], headers: &mut HashMap<usize, isize>) -> Vec<isize> {
   let x86 = !matches!(ix.isa, Isa::Aarch64 | Isa::Thumb2);
   let mut tags = reads
      .iter()
      .enumerate()
      .flat_map(|(at, tag)| {
         reads[at + 1..]
            .iter()
            .take_while(move |value| value.step - tag.step <= PAIR_REACH)
            .filter(move |value| value.base == tag.base && value.offset == tag.offset + 8)
            .map(move |_| *tag)
      })
      .map(|tag| {
         let header = *headers.entry(tag.lock).or_insert_with(|| {
            if x86 && points_at_lock(ix, tag.lock) {
               LOCK_DATA
            } else {
               0
            }
         });
         tag.offset - header
      })
      .filter(|&tag| tag > 0)
      .collect::<Vec<isize>>();
   tags.sort_unstable();
   tags.dedup();
   tags
}

/// The armeabi-v7a hook point, `bool is_staff(&Store, int force)`: the reader
/// whose first branch is `cbz`/`cbnz` on `force`. The other targets patch the
/// field.
fn thumb_check(ix: &Index<'_>, readers: &[Func<'_>]) -> Option<usize> {
   let force = ix.isa.arg(1)?;
   let tests_force = |func: &Func<'_>| {
      func
         .steps()
         .iter()
         .find(|step| matches!(step.op, Op::Branch(_)))
         .is_some_and(|step| {
            matches!(step.native, Native::Thumb(hw)
               if hw & 0xF500 == 0xB100 && (hw & 7) as Reg == force)
         })
   };
   let checks = readers
      .iter()
      .filter(|func| tests_force(func))
      .map(|func| func.start)
      .collect::<Vec<usize>>();
   match checks[..] {
      [only] => Some(only),
      _ => None,
   }
}

/// `flag_override`, and on armeabi-v7a the check function the runtime hooks.
#[derive(Clone, Copy, Debug)]
pub struct Staff {
   pub field: StaffField,
   pub check: Option<usize>,
}

impl fmt::Display for Staff {
   fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
      write!(
         out,
         "tag {:#x}, value {:#x}",
         self.field.tag, self.field.value
      )?;
      self
         .check
         .map_or(Ok(()), |check| write!(out, ", check {check:#x}"))
   }
}

/// The pair the most experiments.rs readers take through a guard, one vote per
/// reader.
pub fn staff(ix: &Index<'_>) -> Found<Staff> {
   let mut headers = HashMap::new();
   let mut votes = BTreeMap::<isize, Vec<Func<'_>>>::new();
   for func in ix.source("ops/experiments.rs") {
      for tag in pairs(ix, &reads(ix, &func), &mut headers) {
         votes.entry(tag).or_default().push(func);
      }
   }
   let mut ranked = votes.into_iter().collect::<Vec<(isize, Vec<Func<'_>>)>>();
   ranked.sort_by_key(|(_, readers)| std::cmp::Reverse(readers.len()));
   let [(tag, readers), rest @ ..] = &ranked[..] else {
      return Err("no experiments.rs reader takes a field pair through a guard".to_owned());
   };
   if let Some((other, _)) = rest.first().filter(|(_, next)| next.len() == readers.len()) {
      return Err(format!(
         "staff pair ties at {} readers between {tag:#x} and {other:#x}",
         readers.len()
      ));
   }
   let tag = usize::try_from(*tag).map_err(|_| "negative staff offset")?;
   let check = if ix.isa == Isa::Thumb2 {
      Some(thumb_check(ix, readers).ok_or("no reader tests its force argument first")?)
   } else {
      None
   };
   Ok(Staff {
      field: StaffField {
         tag,
         value: tag + 8,
      },
      check,
   })
}
