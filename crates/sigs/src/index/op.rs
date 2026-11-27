//! One instruction vocabulary for every ISA Discord ships, so a locator can
//! read a function's calls, address loads and field accesses without knowing
//! whether it runs on x86-64, arm64 or Thumb-2.

use phoenix_hook::{
   arm64::{
      self,
      Insn,
   },
   image::Image,
};

/// The instruction set of an image's code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Isa {
   /// Windows and Linux Desktop. Win64 when `pdata` is set, System V otherwise.
   #[cfg(any(target_arch = "x86_64", target_os = "macos"))]
   X86_64 { win64: bool },
   /// macOS Desktop, iOS and Android arm64-v8a.
   Aarch64,
   /// Android armeabi-v7a.
   Thumb2,
}

/// A general-purpose register, numbered as its ISA encodes it: `rax` 0 to
/// `r15` 15 on x86-64, `x0` to `x30` on arm64 with 31 for `sp`/`xzr`, `r0` to
/// `r15` on Thumb-2.
pub type Reg = u8;

impl Isa {
   /// The ISA of the code this process runs.
   #[cfg(target_arch = "x86_64")]
   pub const HOST: Self = Self::X86_64 {
      win64: cfg!(windows),
   };
   #[cfg(target_arch = "aarch64")]
   pub const HOST: Self = Self::Aarch64;
   #[cfg(target_arch = "arm")]
   pub const HOST: Self = Self::Thumb2;

   /// The register integer argument `index` arrives in, the hidden return
   /// pointer not counted.
   #[must_use]
   pub const fn arg(self, index: usize) -> Option<Reg> {
      #[cfg(any(target_arch = "x86_64", target_os = "macos"))]
      const SYSV: [Reg; 6] = [7, 6, 2, 1, 8, 9];
      #[cfg(any(target_arch = "x86_64", target_os = "macos"))]
      const WIN64: [Reg; 4] = [1, 2, 8, 9];
      let table: &[Reg] = match self {
         #[cfg(any(target_arch = "x86_64", target_os = "macos"))]
         Self::X86_64 { win64: true } => &WIN64,
         #[cfg(any(target_arch = "x86_64", target_os = "macos"))]
         Self::X86_64 { win64: false } => &SYSV,
         Self::Aarch64 => &[0, 1, 2, 3, 4, 5, 6, 7],
         Self::Thumb2 => &[0, 1, 2, 3],
      };
      if index < table.len() {
         Some(table[index])
      } else {
         None
      }
   }

   /// The stack pointer.
   #[must_use]
   pub const fn sp(self) -> Reg {
      match self {
         #[cfg(any(target_arch = "x86_64", target_os = "macos"))]
         Self::X86_64 { .. } => 4,
         Self::Aarch64 => 31,
         Self::Thumb2 => 13,
      }
   }

   /// The register a function returns an integer in.
   #[must_use]
   pub const fn ret(self) -> Reg {
      0
   }
}

/// One instruction, reduced to what locators branch on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
   /// A direct call, or `call [rip + slot]` through a pointer to code.
   Call(usize),
   /// An unconditional direct jump, a tail call when it leaves the function.
   Jump(usize),
   Branch(usize),
   /// `reg = target`, from `lea`, `adrp`+`add`, `adr` or `movw`+`movt`.
   Addr {
      reg:    Reg,
      target: usize,
   },
   /// `reg = base + offset`, from `lea` or `add`, taking a field's address.
   Offset {
      reg:    Reg,
      base:   Reg,
      offset: isize,
   },
   /// `reg = [base + offset]`, `size` bytes.
   Load {
      reg:    Reg,
      base:   Reg,
      offset: isize,
      size:   u8,
   },
   /// `[base + offset] = value`, `size` bytes.
   Store {
      value:  Value,
      base:   Reg,
      offset: isize,
      size:   u8,
   },
   /// A load from or store to a fixed address, `[rip + d]` or `adrp`+`ldr`.
   Global {
      target: usize,
      store:  bool,
   },
   /// `reg = imm`.
   Imm {
      reg:   Reg,
      value: u64,
   },
   /// `dst = src`.
   Move {
      dst: Reg,
      src: Reg,
   },
   /// `cmp reg, imm`.
   Cmp {
      reg:   Reg,
      value: u64,
   },
   /// `cmp [base + offset], imm`, `size` bytes, a field tested in place.
   CmpMem {
      base:   Reg,
      offset: isize,
      size:   u8,
      value:  u64,
   },
   /// An atomic access of `[base + offset]`: a `lock` prefix, an exclusive or
   /// acquire load or store, or a CAS.
   Atomic {
      base:   Reg,
      offset: isize,
   },
   Ret,
   Other,
}

/// What a store writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
   Reg(Reg),
   Imm(u64),
}

/// An instruction at its address, with the ISA's own decoding for the picks a
/// shared [`Op`] cannot express.
#[derive(Clone, Copy, Debug)]
pub struct Step {
   pub at:     usize,
   pub len:    u8,
   pub op:     Op,
   pub native: Native,
}

#[derive(Clone, Copy, Debug)]
pub enum Native {
   #[cfg(any(target_arch = "x86_64", target_os = "macos"))]
   X86(iced_x86::Mnemonic),
   Arm64(Insn),
   Thumb(u32),
}

/// Decodes `[start, end)` of `image`, which holds `isa` code.
pub fn decode(image: &Image<'_>, isa: Isa, start: usize, end: usize) -> Vec<Step> {
   let Some(code) = image.read(start, end.saturating_sub(start)) else {
      return Vec::new();
   };
   match isa {
      #[cfg(any(target_arch = "x86_64", target_os = "macos"))]
      Isa::X86_64 { .. } => x86(image, code, start),
      Isa::Aarch64 => aarch64(code, start),
      Isa::Thumb2 => crate::index::thumb::decode(image, code, start),
   }
}

#[cfg(any(target_arch = "x86_64", target_os = "macos"))]
#[allow(
   clippy::too_many_lines,
   clippy::cast_possible_truncation,
   clippy::cast_possible_wrap,
   clippy::cast_sign_loss,
   reason = "one arm per instruction form, each value bounded by the encoding before the cast"
)]
fn x86(image: &Image<'_>, code: &[u8], ip: usize) -> Vec<Step> {
   use iced_x86::{
      Decoder,
      DecoderOptions,
      FlowControl,
      Instruction,
      Mnemonic,
      OpKind,
      Register,
   };

   let gpr = |register: Register| -> Option<Reg> {
      let full = register.full_register();
      (full.is_gpr64()).then(|| full.number() as Reg)
   };
   let addr = |value: u64| usize::try_from(value).ok();
   let mut decoder = Decoder::with_ip(64, code, ip as u64, DecoderOptions::NONE);
   let mut instruction = Instruction::default();
   let mut steps = Vec::new();
   while decoder.can_decode() {
      decoder.decode_out(&mut instruction);
      if instruction.is_invalid() {
         break;
      }
      let at = addr(instruction.ip()).unwrap_or(0);
      let size = |kind: u32| kind.min(8) as u8;
      let mem_size = instruction.memory_size().size() as u32;
      let rip_target = instruction
         .is_ip_rel_memory_operand()
         .then(|| addr(instruction.ip_rel_memory_address()))
         .flatten();
      let branch = addr(instruction.near_branch_target()).filter(|&target| target != 0);
      let op = match (instruction.flow_control(), instruction.mnemonic()) {
         (FlowControl::Call | FlowControl::IndirectCall, _) => {
            branch
               .or_else(|| rip_target.and_then(|slot| image.read_usize(slot)))
               .filter(|&callee| image.is_code(callee))
               .map_or(Op::Other, Op::Call)
         },
         (FlowControl::UnconditionalBranch, _) => branch.map_or(Op::Other, Op::Jump),
         (FlowControl::IndirectBranch, _) => {
            rip_target
               .and_then(|slot| image.read_usize(slot))
               .filter(|&callee| image.is_code(callee))
               .map_or(Op::Other, Op::Jump)
         },
         (FlowControl::ConditionalBranch, _) => branch.map_or(Op::Other, Op::Branch),
         (FlowControl::Return, _) => Op::Ret,
         (_, Mnemonic::Lea) => {
            let base = gpr(instruction.memory_base())
               .filter(|_| instruction.memory_index() == Register::None);
            match (gpr(instruction.op0_register()), rip_target, base) {
               (Some(reg), Some(target), _) => Op::Addr { reg, target },
               (Some(reg), None, Some(base)) => {
                  Op::Offset {
                     reg,
                     base,
                     offset: instruction.memory_displacement64().cast_signed() as isize,
                  }
               },
               _ => Op::Other,
            }
         },
         (_, Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd) => {
            let base = gpr(instruction.memory_base());
            let offset = instruction.memory_displacement64().cast_signed() as isize;
            match (instruction.op0_kind(), instruction.op1_kind()) {
               (OpKind::Register, OpKind::Memory) => {
                  match (gpr(instruction.op0_register()), rip_target, base) {
                     (_, Some(target), _) => {
                        Op::Global {
                           target,
                           store: false,
                        }
                     },
                     (Some(reg), None, Some(base)) => {
                        Op::Load {
                           reg,
                           base,
                           offset,
                           size: size(mem_size),
                        }
                     },
                     _ => Op::Other,
                  }
               },
               (OpKind::Memory, kind) => {
                  let value = match kind {
                     OpKind::Register => gpr(instruction.op1_register()).map(Value::Reg),
                     _ => Some(Value::Imm(instruction.immediate(1))),
                  };
                  match (rip_target, base, value) {
                     (Some(target), ..) => {
                        Op::Global {
                           target,
                           store: true,
                        }
                     },
                     (None, Some(base), Some(value)) => {
                        Op::Store {
                           value,
                           base,
                           offset,
                           size: size(mem_size),
                        }
                     },
                     _ => Op::Other,
                  }
               },
               (OpKind::Register, OpKind::Register) => {
                  match (
                     gpr(instruction.op0_register()),
                     gpr(instruction.op1_register()),
                  ) {
                     (Some(dst), Some(src)) => Op::Move { dst, src },
                     _ => Op::Other,
                  }
               },
               (OpKind::Register, _) => {
                  gpr(instruction.op0_register()).map_or(Op::Other, |reg| {
                     Op::Imm {
                        reg,
                        value: instruction.immediate(1),
                     }
                  })
               },
               _ => Op::Other,
            }
         },
         _ if instruction.has_lock_prefix() && instruction.memory_index() == Register::None => {
            gpr(instruction.memory_base()).map_or(Op::Other, |base| {
               Op::Atomic {
                  base,
                  offset: instruction.memory_displacement64().cast_signed() as isize,
               }
            })
         },
         (_, Mnemonic::Cmp)
            if instruction.op0_kind() == OpKind::Memory
               && rip_target.is_none()
               && instruction.memory_index() == Register::None =>
         {
            match (gpr(instruction.memory_base()), instruction.op1_kind()) {
               (
                  Some(base),
                  OpKind::Immediate8
                  | OpKind::Immediate8to64
                  | OpKind::Immediate32
                  | OpKind::Immediate8to32
                  | OpKind::Immediate32to64
                  | OpKind::Immediate16,
               ) => {
                  Op::CmpMem {
                     base,
                     offset: instruction.memory_displacement64().cast_signed() as isize,
                     size: size(mem_size),
                     value: instruction.immediate(1),
                  }
               },
               _ => Op::Other,
            }
         },
         (_, Mnemonic::Cmp) if instruction.op0_kind() == OpKind::Register => {
            match (gpr(instruction.op0_register()), instruction.op1_kind()) {
               (
                  Some(reg),
                  OpKind::Immediate8
                  | OpKind::Immediate8to64
                  | OpKind::Immediate32
                  | OpKind::Immediate8to32
                  | OpKind::Immediate32to64
                  | OpKind::Immediate16,
               ) => {
                  Op::Cmp {
                     reg,
                     value: instruction.immediate(1),
                  }
               },
               _ => Op::Other,
            }
         },
         (_, Mnemonic::Xor)
            if instruction.op0_kind() == OpKind::Register
               && instruction.op1_kind() == OpKind::Register
               && instruction.op0_register() == instruction.op1_register() =>
         {
            gpr(instruction.op0_register()).map_or(Op::Other, |reg| Op::Imm { reg, value: 0 })
         },
         _ => {
            rip_target.map_or(Op::Other, |target| {
               Op::Global {
                  target,
                  store: false,
               }
            })
         },
      };
      steps.push(Step {
         at,
         len: instruction.len() as u8,
         op,
         native: Native::X86(instruction.mnemonic()),
      });
   }
   steps
}

#[allow(
   clippy::too_many_lines,
   clippy::cast_possible_truncation,
   clippy::cast_possible_wrap,
   clippy::cast_sign_loss,
   reason = "one arm per instruction form, each value bounded by the encoding before the cast"
)]
fn aarch64(code: &[u8], pc: usize) -> Vec<Step> {
   // The last `adrp` each register got, by step index, and its page.
   let mut pages = [(usize::MAX, 0usize); 32];
   let mut steps = Vec::with_capacity(code.len() / 4);
   for (index, (at, insn)) in arm64::decode_all(code, pc).enumerate() {
      let page = |rn: Reg| {
         let (set, page) = pages[usize::from(rn)];
         (set != usize::MAX && index - set <= PAIR_REACH).then_some(page)
      };
      let op = match insn {
         Insn::Adrp { rd, page } => {
            pages[usize::from(rd)] = (index, page);
            Op::Addr {
               reg:    rd,
               target: page,
            }
         },
         Insn::AddImm { rd, rn, imm } => {
            match page(rn) {
               Some(page) => {
                  Op::Addr {
                     reg:    rd,
                     target: page.wrapping_add(imm),
                  }
               },
               None if imm == 0 => Op::Move { dst: rd, src: rn },
               None => {
                  Op::Offset {
                     reg:    rd,
                     base:   rn,
                     offset: imm.cast_signed(),
                  }
               },
            }
         },
         Insn::Load {
            rt,
            rn,
            offset,
            size,
         } => {
            page(rn).map_or_else(
               || {
                  Op::Load {
                     reg:    rt,
                     base:   rn,
                     offset: offset.cast_signed(),
                     size:   size as u8,
                  }
               },
               |page| {
                  Op::Global {
                     target: page.wrapping_add(offset),
                     store:  false,
                  }
               },
            )
         },
         Insn::Store {
            rt,
            rn,
            offset,
            size,
         } => {
            page(rn).map_or_else(
               || {
                  Op::Store {
                     value:  Value::Reg(rt),
                     base:   rn,
                     offset: offset.cast_signed(),
                     size:   size as u8,
                  }
               },
               |page| {
                  Op::Global {
                     target: page.wrapping_add(offset),
                     store:  true,
                  }
               },
            )
         },
         Insn::MovZ { rd, imm, .. } => {
            Op::Imm {
               reg:   rd,
               value: imm,
            }
         },
         Insn::MovN { rd, imm, wide } => {
            Op::Imm {
               reg:   rd,
               value: if wide { !imm } else { u64::from(!(imm as u32)) },
            }
         },
         Insn::MovReg { rd, rm: 31, .. } => {
            Op::Imm {
               reg:   rd,
               value: 0,
            }
         },
         Insn::MovReg { rd, rm, .. } => Op::Move { dst: rd, src: rm },
         Insn::CmpImm { rn, imm, .. } => {
            Op::Cmp {
               reg:   rn,
               value: imm as u64,
            }
         },
         Insn::Bl { target } => Op::Call(target),
         Insn::B { target } => Op::Jump(target),
         Insn::BCond { target, .. } | Insn::Cbz { target, .. } | Insn::Tbz { target, .. } => {
            Op::Branch(target)
         },
         Insn::Ret => Op::Ret,
         // Load/store exclusive, CAS and the LSE read-modify-writes.
         Insn::Other(word)
            if word & 0x3F00_0000 == 0x0800_0000 || word & 0x3F20_0C00 == 0x3820_0000 =>
         {
            Op::Atomic {
               base:   ((word >> 5) & 0x1F) as Reg,
               offset: 0,
            }
         },
         _ => Op::Other,
      };
      steps.push(Step {
         at,
         len: 4,
         op,
         native: Native::Arm64(insn),
      });
   }
   steps
}

/// How far after an `adrp` its `add` or `ldr` is looked for, as in
/// [`arm64::code_refs`].
pub const PAIR_REACH: usize = 12;
