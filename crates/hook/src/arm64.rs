//! `AArch64` decoding for the locators that read arm64 code (macOS Phoenix):
//! the few instruction forms they match on, and the `adrp` pairs that load an
//! address.

use std::ops::Range;

use crate::image::Image;

/// A register number, 31 for `sp`/`xzr` depending on the instruction.
pub type Reg = u8;

/// One decoded instruction. Anything else is [`Insn::Other`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Insn {
   /// `adrp rd, page`.
   Adrp {
      rd:   Reg,
      page: usize,
   },
   /// `add rd, rn, #imm` (`mov rd, sp` included).
   AddImm {
      rd:  Reg,
      rn:  Reg,
      imm: usize,
   },
   /// `cmp rn, #imm`, `subs xzr/wzr, rn, #imm`.
   CmpImm {
      rn:   Reg,
      imm:  usize,
      wide: bool,
   },
   /// `ldr`/`ldrb`/`ldrh` with an unsigned scaled offset: `size` bytes at
   /// `[rn, #offset]`.
   Load {
      rt:     Reg,
      rn:     Reg,
      offset: usize,
      size:   usize,
   },
   /// `str`/`strb`/`strh` with an unsigned scaled offset.
   Store {
      rt:     Reg,
      rn:     Reg,
      offset: usize,
      size:   usize,
   },
   /// `movz rd, #imm, lsl #shift`.
   MovZ {
      rd:   Reg,
      imm:  u64,
      wide: bool,
   },
   /// `movn rd, #imm` (the value is `!imm`).
   MovN {
      rd:   Reg,
      imm:  u64,
      wide: bool,
   },
   /// `mov rd, rm` (`orr rd, xzr, rm`).
   MovReg {
      rd:   Reg,
      rm:   Reg,
      wide: bool,
   },
   /// `and rd, rn, #0xff` style masks are left as [`Insn::Other`]; this is
   /// `cset rd, cond`.
   Cset {
      rd:   Reg,
      cond: u8,
   },
   Bl {
      target: usize,
   },
   B {
      target: usize,
   },
   BCond {
      cond:   u8,
      target: usize,
   },
   Cbz {
      rt:      Reg,
      nonzero: bool,
      target:  usize,
   },
   Tbz {
      rt:      Reg,
      bit:     u8,
      nonzero: bool,
      target:  usize,
   },
   /// A pre- or post-indexed load or store (`[rn, #imm]!`, `[rn], #imm`),
   /// integer or SIMD, which moves `rn` by `imm`.
   Writeback {
      rt:   Reg,
      rn:   Reg,
      imm:  isize,
      load: bool,
   },
   Ret,
   Br {
      rn: Reg,
   },
   Blr {
      rn: Reg,
   },
   Other(u32),
}

/// Condition codes as encoded.
pub mod cond {
   pub const EQ: u8 = 0;
   pub const NE: u8 = 1;
   pub const HS: u8 = 2;
   pub const LO: u8 = 3;
   pub const HI: u8 = 8;
   pub const LS: u8 = 9;
}

const fn sign_extend(value: u32, bits: u32) -> isize {
   let shift = 32 - bits;
   (((value << shift).cast_signed()) >> shift) as isize
}

const fn rel(pc: usize, imm: u32, bits: u32) -> usize {
   pc.wrapping_add_signed(sign_extend(imm, bits) * 4)
}

/// Decodes `word` at `pc`.
#[must_use]
#[expect(
   clippy::too_many_lines,
   clippy::cast_possible_truncation,
   reason = "one arm per instruction form, each field masked to its width before the cast"
)]
pub fn decode(word: u32, pc: usize) -> Insn {
   let rd = (word & 0x1F) as Reg;
   let rn = ((word >> 5) & 0x1F) as Reg;
   let wide = word >> 31 == 1;
   match word {
      _ if word == 0xD65F_03C0 => Insn::Ret,
      _ if word & 0xFFFF_FC1F == 0xD61F_0000 => Insn::Br { rn },
      _ if word & 0xFFFF_FC1F == 0xD63F_0000 => Insn::Blr { rn },
      _ if word & 0x9F00_0000 == 0x9000_0000 => {
         let immlo = (word >> 29) & 3;
         let immhi = (word >> 5) & 0x7_FFFF;
         let imm = sign_extend((immhi << 2) | immlo, 21) << 12;
         Insn::Adrp {
            rd,
            page: (pc & !0xFFF).wrapping_add_signed(imm),
         }
      },
      // add (immediate), 32 or 64 bit, flags not set.
      _ if word & 0x7F80_0000 == 0x1100_0000 => {
         let shift = (word >> 22) & 1;
         let imm = ((word >> 10) & 0xFFF) as usize;
         Insn::AddImm {
            rd,
            rn,
            imm: imm << (12 * shift),
         }
      },
      // subs (immediate) to the zero register: cmp.
      _ if word & 0x7F80_0000 == 0x7100_0000 && rd == 31 => {
         let shift = (word >> 22) & 1;
         let imm = ((word >> 10) & 0xFFF) as usize;
         Insn::CmpImm {
            rn,
            imm: imm << (12 * shift),
            wide,
         }
      },
      // ldr/str (immediate, pre- or post-index), integer or SIMD.
      _ if word & 0x3B20_0400 == 0x3800_0400 => {
         Insn::Writeback {
            rt: rd,
            rn,
            imm: sign_extend((word >> 12) & 0x1FF, 9),
            load: (word >> 22) & 1 == 1,
         }
      },
      // ldr/str (unsigned immediate), integer registers: size 0..3, opc 0/1.
      _ if word & 0x3B00_0000 == 0x3900_0000 && (word >> 26) & 1 == 0 => {
         let size = 1usize << (word >> 30);
         let opc = (word >> 22) & 3;
         let offset = ((word >> 10) & 0xFFF) as usize * size;
         match opc {
            0 => {
               Insn::Store {
                  rt: rd,
                  rn,
                  offset,
                  size,
               }
            },
            1 => {
               Insn::Load {
                  rt: rd,
                  rn,
                  offset,
                  size,
               }
            },
            _ => Insn::Other(word),
         }
      },
      _ if word & 0x7F80_0000 == 0x5280_0000 => {
         let hw = (word >> 21) & 3;
         Insn::MovZ {
            rd,
            imm: u64::from((word >> 5) & 0xFFFF) << (16 * hw),
            wide,
         }
      },
      _ if word & 0x7F80_0000 == 0x1280_0000 => {
         let hw = (word >> 21) & 3;
         Insn::MovN {
            rd,
            imm: u64::from((word >> 5) & 0xFFFF) << (16 * hw),
            wide,
         }
      },
      // orr rd, zr, rm (no shift).
      _ if word & 0x7FE0_FFE0 == 0x2A00_03E0 => {
         Insn::MovReg {
            rd,
            rm: ((word >> 16) & 0x1F) as Reg,
            wide,
         }
      },
      // csinc rd, zr, zr, invert(cond).
      _ if word & 0x7FFF_0FE0 == 0x1A9F_07E0 => {
         Insn::Cset {
            rd,
            cond: (((word >> 12) & 0xF) ^ 1) as u8,
         }
      },
      _ if word & 0xFC00_0000 == 0x9400_0000 => {
         Insn::Bl {
            target: rel(pc, word & 0x03FF_FFFF, 26),
         }
      },
      _ if word & 0xFC00_0000 == 0x1400_0000 => {
         Insn::B {
            target: rel(pc, word & 0x03FF_FFFF, 26),
         }
      },
      _ if word & 0xFF00_0010 == 0x5400_0000 => {
         Insn::BCond {
            cond:   (word & 0xF) as u8,
            target: rel(pc, (word >> 5) & 0x7_FFFF, 19),
         }
      },
      _ if word & 0x7E00_0000 == 0x3400_0000 => {
         Insn::Cbz {
            rt:      rd,
            nonzero: (word >> 24) & 1 == 1,
            target:  rel(pc, (word >> 5) & 0x7_FFFF, 19),
         }
      },
      _ if word & 0x7E00_0000 == 0x3600_0000 => {
         Insn::Tbz {
            rt:      rd,
            bit:     (((word >> 31) << 5) | ((word >> 19) & 0x1F)) as u8,
            nonzero: (word >> 24) & 1 == 1,
            target:  rel(pc, (word >> 5) & 0x3FFF, 14),
         }
      },
      _ => Insn::Other(word),
   }
}

/// The instructions of `code` at `pc`, one per word.
pub fn decode_all(code: &[u8], pc: usize) -> impl Iterator<Item = (usize, Insn)> + '_ {
   code
      .as_chunks::<4>()
      .0
      .iter()
      .enumerate()
      .map(move |(at, &word)| {
         let addr = pc + at * 4;
         let word = u32::from_le_bytes(word);
         (addr, decode(word, addr))
      })
}

/// The instruction at `addr`.
#[must_use]
pub fn decode_at(image: &Image<'_>, addr: usize) -> Option<Insn> {
   image.read_u32(addr).map(|word| decode(word, addr))
}

/// Decodes up to `count` arm64 instructions starting at `pc` into `(addr, text)`.
#[must_use]
pub fn disasm(code: &[u8], pc: usize, count: usize) -> Vec<(usize, String)> {
   code
      .as_chunks::<4>()
      .0
      .iter()
      .take(count)
      .enumerate()
      .map(|(i, &bytes)| {
         let addr = pc + i * 4;
         let word = u32::from_le_bytes(bytes);
         (addr, format_insn(word, addr))
      })
      .collect()
}

fn format_insn(word: u32, pc: usize) -> String {
   let x = |r: Reg, wide: bool| {
      match (r, wide) {
         (31, true) => "xzr".to_owned(),
         (31, false) => "wzr".to_owned(),
         (_, true) => format!("x{r}"),
         (_, false) => format!("w{r}"),
      }
   };
   let sp = |r: Reg| {
      if r == 31 {
         "sp".to_owned()
      } else {
         format!("x{r}")
      }
   };
   let cond_name = |c: u8| {
      match c {
         0 => "eq",
         1 => "ne",
         2 => "hs",
         3 => "lo",
         4 => "mi",
         5 => "pl",
         6 => "vs",
         7 => "vc",
         8 => "hi",
         9 => "ls",
         10 => "ge",
         11 => "lt",
         12 => "gt",
         13 => "le",
         14 => "al",
         _ => "nv",
      }
   };
   match decode(word, pc) {
      Insn::Adrp { rd, page } => format!("adrp {}, {page:#x}", x(rd, true)),
      Insn::AddImm { rd, rn, imm } => format!("add {}, {}, #{imm:#x}", sp(rd), sp(rn)),
      Insn::CmpImm { rn, imm, wide } => format!("cmp {}, #{imm:#x}", x(rn, wide)),
      Insn::Load {
         rt,
         rn,
         offset,
         size,
      } => {
         let (op, wide) = match size {
            1 => ("ldrb", false),
            2 => ("ldrh", false),
            4 => ("ldr", false),
            _ => ("ldr", true),
         };
         format!("{op} {}, [{}, #{offset:#x}]", x(rt, wide), sp(rn))
      },
      Insn::Store {
         rt,
         rn,
         offset,
         size,
      } => {
         let (op, wide) = match size {
            1 => ("strb", false),
            2 => ("strh", false),
            4 => ("str", false),
            _ => ("str", true),
         };
         format!("{op} {}, [{}, #{offset:#x}]", x(rt, wide), sp(rn))
      },
      Insn::MovZ { rd, imm, wide } => format!("mov {}, #{imm:#x}", x(rd, wide)),
      Insn::MovN { rd, imm, wide } => format!("movn {}, #{imm:#x}", x(rd, wide)),
      Insn::MovReg { rd, rm, wide } => format!("mov {}, {}", x(rd, wide), x(rm, wide)),
      Insn::Cset { rd, cond } => format!("cset {}, {}", x(rd, false), cond_name(cond)),
      Insn::Bl { target } => format!("bl {target:#x}"),
      Insn::B { target } => format!("b {target:#x}"),
      Insn::BCond { cond, target } => format!("b.{} {target:#x}", cond_name(cond)),
      Insn::Cbz {
         rt,
         nonzero,
         target,
      } => {
         let op = if nonzero { "cbnz" } else { "cbz" };
         format!("{op} x{rt}, {target:#x}")
      },
      Insn::Tbz {
         rt,
         bit,
         nonzero,
         target,
      } => {
         let op = if nonzero { "tbnz" } else { "tbz" };
         format!("{op} x{rt}, #{bit}, {target:#x}")
      },
      Insn::Writeback { rt, rn, imm, load } => {
         let op = if load { "ldr" } else { "str" };
         format!("{op} x{rt}, [{}, #{imm:#x}]!", sp(rn))
      },
      Insn::Ret => "ret".to_owned(),
      Insn::Br { rn } => format!("br {}", x(rn, true)),
      Insn::Blr { rn } => format!("blr {}", x(rn, true)),
      Insn::Other(w) => format!(".word {w:#010x}"),
   }
}

/// The decoded body of the function holding `addr`, from its start.
#[must_use]
pub fn function(image: &Image<'_>, addr: usize) -> Option<(usize, Vec<(usize, Insn)>)> {
   let (start, end) = image.function_bounds(addr)?;
   let code = image.read(start, end - start)?;
   Some((start, decode_all(code, start).collect()))
}

/// How far after an `adrp` its `add` or `ldr` is looked for. Compilers keep
/// the pair close but schedule other instructions between them.
const PAIR_REACH: usize = 12;

/// Words each worker thread scans when building the reference index.
const CHUNK_WORDS: usize = 1 << 21;

/// Frees the cached arm64 reference index once startup locators have finished.
pub fn release_ref_index() {
   *REF_INDEX
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
}

struct RefIndex {
   base:       usize,
   exec_bytes: usize,
   // packed `((target - base) << 32) | (site - base)`, sorted for binary search
   refs:       Vec<u64>,
}

static REF_INDEX: std::sync::Mutex<Option<RefIndex>> = std::sync::Mutex::new(None);

fn exec_summary(image: &Image<'_>) -> Option<(usize, usize, usize)> {
   let base = image.segments.iter().map(|seg| seg.addr).min()?;
   let mut exec_bytes = 0usize;
   let mut max_end = base;
   for seg in &image.segments {
      if seg.executable {
         exec_bytes = exec_bytes.saturating_add(seg.bytes.len());
      }
      max_end = max_end.max(seg.addr.saturating_add(seg.bytes.len()));
   }
   // Only cache real binaries; small test images scan directly.
   if exec_bytes < (1 << 20) || max_end.saturating_sub(base) > u32::MAX as usize {
      return None;
   }
   Some((base, exec_bytes, max_end))
}

fn with_index<T>(image: &Image<'_>, f: impl FnOnce(&RefIndex) -> T) -> Option<T> {
   let (base, exec_bytes, max_end) = exec_summary(image)?;
   let mut guard = REF_INDEX
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner);
   let matches = guard
      .as_ref()
      .is_some_and(|idx| idx.base == base && idx.exec_bytes == exec_bytes);
   if !matches {
      let mut refs = build_ref_index(image, base, max_end)?;
      refs.sort_unstable();
      *guard = Some(RefIndex {
         base,
         exec_bytes,
         refs,
      });
   }
   Some(f(guard.as_ref()?))
}

fn indexed_ranges(image: &Image<'_>, targets: &[Range<usize>]) -> Option<Vec<(usize, usize)>> {
   with_index(image, |idx| {
      let mut out = Vec::new();
      for range in targets {
         if range.is_empty() || range.end <= idx.base {
            continue;
         }
         let low = u64::try_from(range.start.saturating_sub(idx.base))
            .unwrap_or(u64::MAX)
            .min(u64::from(u32::MAX));
         let high = u64::try_from((range.end - 1).saturating_sub(idx.base))
            .unwrap_or(u64::MAX)
            .min(u64::from(u32::MAX));
         let start = idx.refs.partition_point(|&r| (r >> 32) < low);
         let end = idx.refs.partition_point(|&r| (r >> 32) <= high);
         out.extend(idx.refs[start..end].iter().map(|&r| {
            (
               idx.base + (r & 0xFFFF_FFFF) as usize,
               idx.base + (r >> 32) as usize,
            )
         }));
      }
      out
   })
}

/// Scans `words[from..to]` (warming `adrp` pages up to `PAIR_REACH` words
/// early) and invokes `on_ref(site, target)` for every `adrp` pair and direct
/// branch in `[from, to)`.
fn scan_chunk_refs(
   segment_addr: usize,
   words: &[[u8; 4]],
   from: usize,
   to: usize,
   mut on_ref: impl FnMut(usize, usize),
) {
   // The last `adrp` each register got, by its instruction index.
   let mut pages = [(usize::MAX, 0usize); 32];
   let warm = from.saturating_sub(PAIR_REACH);
   for (offset, &raw) in words[warm..to].iter().enumerate() {
      let index = warm + offset;
      let pc = segment_addr + index * 4;
      let word = u32::from_le_bytes(raw);
      let paired = |rn: Reg, imm: usize| {
         let (at, page) = pages[usize::from(rn)];
         (at != usize::MAX && index - at <= PAIR_REACH).then(|| page.wrapping_add(imm))
      };
      let target = match decode(word, pc) {
         Insn::Adrp { rd, page } => {
            pages[usize::from(rd)] = (index, page);
            None
         },
         Insn::AddImm { rn, imm, .. } => paired(rn, imm),
         Insn::Load { rn, offset, .. } | Insn::Store { rn, offset, .. } => paired(rn, offset),
         Insn::Bl { target } | Insn::B { target } => Some(target),
         _ => None,
      };
      if index >= from
         && let Some(target) = target
      {
         on_ref(pc, target);
      }
   }
}

fn build_ref_index(image: &Image<'_>, base: usize, max_end: usize) -> Option<Vec<u64>> {
   let mut all = Vec::new();
   for segment in image.segments.iter().filter(|segment| segment.executable) {
      let words = segment.bytes.as_chunks::<4>().0;
      let chunks = words.len().div_ceil(CHUNK_WORDS);
      let parts: Option<Vec<Vec<u64>>> = std::thread::scope(|scope| {
         #[expect(
            clippy::needless_collect,
            reason = "spawn every chunk worker before joining"
         )]
         let handles: Vec<_> = (0..chunks)
            .map(|chunk| {
               scope.spawn(move || {
                  let start = chunk * CHUNK_WORDS;
                  let end = (start + CHUNK_WORDS).min(words.len());
                  let mut found = Vec::new();
                  scan_chunk_refs(segment.addr, words, start, end, |pc, target| {
                     if target >= base
                        && target < max_end
                        && pc >= base
                        && let (Ok(t_rva), Ok(s_rva)) =
                           (u32::try_from(target - base), u32::try_from(pc - base))
                     {
                        found.push((u64::from(t_rva) << 32) | u64::from(s_rva));
                     }
                  });
                  found
               })
            })
            .collect();
         handles
            .into_iter()
            .map(|handle| handle.join().ok())
            .collect()
      });
      let parts = parts?;
      let total: usize = parts.iter().map(Vec::len).sum();
      all.reserve(total);
      for part in parts {
         all.extend(part);
      }
   }
   Some(all)
}

/// `(site, target)` for every `adrp` pair (`add` or load) and direct branch in
/// executable code that lands in one of `targets`. The site is the pair's
/// second instruction.
///
/// `targets` are sorted and disjoint, so many anchors cost one pass.
#[must_use]
pub fn code_refs(image: &Image<'_>, targets: &[Range<usize>]) -> Vec<(usize, usize)> {
   if targets.is_empty() {
      return Vec::new();
   }
   if let Some(found) = indexed_ranges(image, targets) {
      return found;
   }
   let wanted = |target: &usize| {
      targets
         .get(targets.partition_point(|range| range.end <= *target))
         .is_some_and(|range| range.contains(target))
   };
   let threads = std::thread::available_parallelism().map_or(1, usize::from);
   let mut found = Vec::new();
   for segment in image.segments.iter().filter(|segment| segment.executable) {
      let words = segment.bytes.as_chunks::<4>().0;
      let chunk = words.len().div_ceil(threads).max(PAIR_REACH);
      std::thread::scope(|scope| {
         let handles: Vec<_> = (0..words.len())
            .step_by(chunk)
            .map(|from| {
               scope.spawn(move || {
                  let to = (from + chunk).min(words.len());
                  let mut part = Vec::new();
                  scan_chunk_refs(segment.addr, words, from, to, |pc, target| {
                     if wanted(&target) {
                        part.push((pc, target));
                     }
                  });
                  part
               })
            })
            .collect();
         for handle in handles {
            found.extend(handle.join().unwrap_or_default());
         }
      });
   }
   found
}

/// Bytes [`absolute_jump`] writes over a hooked function's start.
pub const JUMP_LEN: usize = 16;

/// `ldr x16, #8; br x16; .quad to`, which clobbers only `x16`, the
/// intra-procedure scratch register calls may already clobber.
#[must_use]
pub fn absolute_jump(to: usize) -> [u8; JUMP_LEN] {
   let mut jump = [0; JUMP_LEN];
   jump[..4].copy_from_slice(&0x5800_0050u32.to_le_bytes());
   jump[4..8].copy_from_slice(&0xD61F_0200u32.to_le_bytes());
   jump[8..].copy_from_slice(&(to as u64).to_le_bytes());
   jump
}

/// `ldr x3, #16; ldr x16, #20; br x16; nop; .quad fallback; .quad detour`:
/// jumps to `detour` with `fallback` in `x3`, preserving `x0..=x2`.
#[must_use]
pub fn pass_x3_stub(detour: usize, fallback: usize) -> [u8; 32] {
   let mut stub = [0; 32];
   stub[..4].copy_from_slice(&0x5800_0083u32.to_le_bytes());
   stub[4..8].copy_from_slice(&0x5800_00B0u32.to_le_bytes());
   stub[8..12].copy_from_slice(&0xD61F_0200u32.to_le_bytes());
   stub[12..16].copy_from_slice(&0xD503_201Fu32.to_le_bytes());
   stub[16..24].copy_from_slice(&(fallback as u64).to_le_bytes());
   stub[24..32].copy_from_slice(&(detour as u64).to_le_bytes());
   stub
}

/// `code`, the instructions displaced from `from`, rewritten to run anywhere:
/// PC-relative ones load or branch to their absolute target through `x16`
/// instead. `None` when one can't be moved, like a literal load.
#[must_use]
pub fn relocate(code: &[u8], from: usize) -> Option<Vec<u8>> {
   const LDR_X16_8: u32 = 0x5800_0050;
   const BR_X16: u32 = 0xD61F_0200;
   const SKIP_LITERAL: u32 = 0x1400_0003;

   let mut out = Vec::new();
   let mut words = |words: &[u32]| words.iter().for_each(|word| out.extend(word.to_le_bytes()));
   for (at, &raw) in code.as_chunks::<4>().0.iter().enumerate() {
      let pc = from + at * 4;
      let word = u32::from_le_bytes(raw);
      let quad = |value: usize| {
         let bytes = (value as u64).to_le_bytes();
         [
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
         ]
      };
      // Conditional branches keep their condition and land on a local veneer
      // two words on: `cond +8; b past; ldr x16, #8; br x16; .quad target`.
      let veneer = |word: u32, target: usize| {
         let [low, high] = quad(target);
         [word, 0x1400_0005, LDR_X16_8, BR_X16, low, high]
      };
      match decode(word, pc) {
         Insn::Adrp { rd, page: target } => {
            let [low, high] = quad(target);
            words(&[0x5800_0040 | u32::from(rd), SKIP_LITERAL, low, high]);
         },
         Insn::B { target } => {
            let [low, high] = quad(target);
            words(&[LDR_X16_8, BR_X16, low, high]);
         },
         Insn::Bl { target } => {
            // `ldr x16, #12; blr x16; b past; .quad target`.
            let [low, high] = quad(target);
            words(&[0x5800_0070, 0xD63F_0200, SKIP_LITERAL, low, high]);
         },
         Insn::BCond { target, .. } | Insn::Cbz { target, .. } => {
            words(&veneer((word & 0xFF00_001F) | (2 << 5), target));
         },
         Insn::Tbz { target, .. } => words(&veneer((word & 0xFFF8_001F) | (2 << 5), target)),
         // `adr` and literal loads.
         _ if word & 0x9F00_0000 == 0x1000_0000 || word & 0x3B00_0000 == 0x1800_0000 => {
            return None;
         },
         _ => words(&[word]),
      }
   }
   Some(out)
}

/// `mov xd, xm`.
const fn mov(d: u32, m: u32) -> u32 {
   0xAA00_03E0 | (m << 16) | d
}

/// Code that calls `target`, which returns through `x8`, the x86-64 way.
///
/// The runtime is written for x86-64's convention: the return slot comes
/// first, the arguments follow (up to seven), and the slot comes back in `x0`.
#[must_use]
pub fn sret_caller(target: usize) -> Vec<u8> {
   let mut words = vec![
      0xA9BE_7BFD, // stp x29, x30, [sp, #-32]!
      0x9100_03FD, // mov x29, sp
      0xF900_0BF3, // str x19, [sp, #16]
      mov(19, 0),
      mov(8, 0),
   ];
   words.extend((0..7).map(|reg| mov(reg, reg + 1)));
   words.extend([
      0x5800_00D0, // ldr x16, #24: the target below
      0xD63F_0200, // blr x16
      mov(0, 19),
      0xF940_0BF3, // ldr x19, [sp, #16]
      0xA8C2_7BFD, // ldp x29, x30, [sp], #32
      0xD65F_03C0, // ret
   ]);
   let mut code = words
      .iter()
      .flat_map(|word| word.to_le_bytes())
      .collect::<Vec<u8>>();
   code.extend((target as u64).to_le_bytes());
   code
}

/// Code that takes an arm64 call and hands it to `detour` the x86-64 way.
///
/// The return slot moves from `x8` to the first argument and the arguments
/// after it, as [`sret_caller`] passes them. The arm64 caller ignores `x0` on
/// return.
#[must_use]
pub fn sret_callee(detour: usize) -> Vec<u8> {
   let mut words = (1..8)
      .rev()
      .map(|reg| mov(reg, reg - 1))
      .collect::<Vec<u32>>();
   words.push(mov(0, 8));
   let mut code = words
      .iter()
      .flat_map(|word| word.to_le_bytes())
      .collect::<Vec<u8>>();
   code.extend(absolute_jump(detour));
   code
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn relocates_branches_to_their_absolute_targets() {
      // bl +0x100 at 0x1000, then a plain `mov x29, sp`.
      let code = [0x9400_0040u32, 0x9100_03FD]
         .iter()
         .flat_map(|word| word.to_le_bytes())
         .collect::<Vec<u8>>();
      let moved = relocate(&code, 0x1000).expect("movable");
      let words = moved
         .as_chunks::<4>()
         .0
         .iter()
         .map(|&word| u32::from_le_bytes(word))
         .collect::<Vec<u32>>();
      assert_eq!(words, [
         0x5800_0070,
         0xD63F_0200,
         0x1400_0003,
         0x1100,
         0,
         0x9100_03FD
      ]);
      // `adr x0, #0` has no absolute form here.
      assert_eq!(relocate(&0x1000_0000u32.to_le_bytes(), 0), None);
   }

   #[test]
   fn sret_thunks_reach_their_targets() {
      let caller = sret_caller(0x1234_5678_9ABC);
      let ldr = caller
         .as_chunks::<4>()
         .0
         .iter()
         .position(|&word| u32::from_le_bytes(word) == 0x5800_00D0)
         .expect("loads its target");
      assert_eq!(caller.len() % 8, 0);
      assert_eq!(&caller[ldr * 4 + 24..], 0x1234_5678_9ABCu64.to_le_bytes());
      let entry = sret_callee(0x42);
      assert_eq!(&entry[entry.len() - 8..], 0x42u64.to_le_bytes());
      assert_eq!(
         u32::from_le_bytes(entry[28..32].try_into().unwrap()),
         mov(0, 8)
      );
   }

   #[test]
   fn decodes_writeback_loads() {
      // ldr q0, [x3, #0xb8]!
      assert_eq!(decode(0x3CCB_8C60, 0), Insn::Writeback {
         rt:   0,
         rn:   3,
         imm:  0xB8,
         load: true,
      });
      // ldr w8, [x3, #0xe8]!
      assert_eq!(decode(0xB84E_8C68, 0), Insn::Writeback {
         rt:   8,
         rn:   3,
         imm:  0xE8,
         load: true,
      });
   }

   #[test]
   fn decodes_the_forms_locators_match() {
      assert_eq!(decode(0xD65F_03C0, 0), Insn::Ret);
      assert_eq!(decode(0x7100_081F, 0), Insn::CmpImm {
         rn:   0,
         imm:  2,
         wide: false,
      });
      assert_eq!(decode(0x1A9F_07E0, 0), Insn::Cset {
         rd:   0,
         cond: cond::NE,
      });
      assert_eq!(decode(0x1A9F_17E0, 0), Insn::Cset {
         rd:   0,
         cond: cond::EQ,
      });
      assert_eq!(decode(0x5280_0040, 0), Insn::MovZ {
         rd:   0,
         imm:  2,
         wide: false,
      });
      // bl -0x30a8 at 0x10000.
      assert_eq!(decode(0x97FF_F3D6, 0x10000), Insn::Bl {
         target: 0x10000 - 0x30A8,
      });
   }
}
