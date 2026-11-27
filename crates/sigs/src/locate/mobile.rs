//! Locators for the Android and iOS hosts, one Rust tree.

use crate::{
   Found,
   index::{
      Index,
      Op,
      Step,
   },
};

/// The access gate's two evaluators, which open it when both return
/// `Some(true)`. They share a body: compare the gate state with 2, read a
/// flag byte off the first argument, and return 2 (`None`) early.
pub fn access_gate(ix: &Index<'_>) -> Found<[usize; 2]> {
   const HEAD: usize = 12;
   let this = ix.isa.arg(0).ok_or("no first argument register")?;
   let ret = ix.isa.ret();
   let shaped = |head: &[Step]| {
      let mut ops = head.iter().map(|step| step.op);
      ops.any(|op| matches!(op, Op::Cmp { value: 2, .. }))
         && ops.any(|op| matches!(op, Op::Load { base, size: 1, .. } if base == this))
         && ops.any(|op| matches!(op, Op::Imm { reg, value: 2 } if reg == ret))
         && ops.next() == Some(Op::Ret)
   };
   let mut evaluators = ix
      .heads(HEAD, shaped)
      .into_iter()
      .map(|func| func.start)
      .collect::<Vec<usize>>();
   evaluators.sort_unstable();
   match evaluators[..] {
      [first, second] => Ok([first, second]),
      _ => {
         Err(format!(
            "access gate matched {} evaluators",
            evaluators.len()
         ))
      },
   }
}
