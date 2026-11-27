//! The chat's message rows: `MessageRow::render`, the body builder it calls,
//! and the fields their arguments keep the message in.

use std::ops::Range;

use crate::{
   Found,
   index::{
      Func,
      Index,
      Op,
      Reg,
      Step,
   },
};

/// Where a row or a message keeps a field the locators read.
const FIELD: Range<isize> = 0x100..0x2000;

/// How far before a `message-content-` load its id argument is formed. The
/// `&message.id` helper on Linux branches between two templates in between.
const ARG_REACH: usize = 32;

/// `MessageRow::render`, and both paths from its row to the message id.
#[derive(Clone, Copy, Debug)]
pub struct MessageRow {
   pub func:       usize,
   /// `row + id` holds the row's own copy of the id.
   pub id:         usize,
   /// `row + rc` holds the message's `Rc`.
   pub rc:         usize,
   /// The message inside the `Rc` allocation.
   pub value:      usize,
   /// `message + message_id` holds the id.
   pub message_id: usize,
}

/// The one caller of every helper formatting `message-content-{id}`. One
/// helper takes the row, opens with `message = row.rc + value` and formats
/// `&row.id`. The others take the message and format `&message.id`.
pub fn message_row(ix: &Index<'_>) -> Found<MessageRow> {
   const NEEDLE: &[u8] = b"\x10message-content-";
   let templates = ix.text(NEEDLE);
   let helpers = ix.literal(NEEDLE);
   if helpers.len() < 2 {
      return Err(format!("{} message-content helpers", helpers.len()));
   }
   let func = helpers
      .iter()
      .map(Func::callers)
      .reduce(|common, parents| common.and(&parents))
      .ok_or("no message-content helper")?
      .one("MessageRow::render")?;

   let (mut row, mut message) = (None, None);
   for helper in helpers.iter() {
      let steps = helper.steps();
      let id = formatted(ix, &steps, &templates)
         .ok_or_else(|| format!("message-content helper {helper:?} formats no field"))?;
      match (rc_deref(ix, &steps), row) {
         (Some(path), None) => row = Some((id, path)),
         (Some(_), Some(_)) => return Err("two helpers take the row".to_owned()),
         (None, _) if message.is_some_and(|known| known != id) => {
            return Err("the message helpers format different fields".to_owned());
         },
         (None, _) => message = Some(id),
      }
   }
   let (id, (rc, value)) = row.ok_or("no message-content helper takes the row")?;
   Ok(MessageRow {
      func: func.start,
      id,
      rc,
      value,
      message_id: message.ok_or("no message-content helper takes the message")?,
   })
}

/// The stack pointer and the frame pointers the prologue sets from it, like
/// Win64's `lea rbp, [rsp + n]` and arm64's `add x29, sp, #n`.
fn frame(ix: &Index<'_>, steps: &[Step]) -> Vec<Reg> {
   const PROLOGUE: usize = 16;
   let sp = ix.isa.sp();
   let mut regs = vec![sp];
   regs.extend(steps.iter().take(PROLOGUE).filter_map(|step| {
      match step.op {
         Op::Offset { reg, base, .. }
         | Op::Move {
            dst: reg,
            src: base,
         } if base == sp => Some(reg),
         _ => None,
      }
   }));
   regs
}

/// The field whose address is formed last before a load of `templates`.
fn formatted(ix: &Index<'_>, steps: &[Step], templates: &[usize]) -> Option<usize> {
   let frame = frame(ix, steps);
   steps
      .iter()
      .enumerate()
      .filter(|(_, step)| matches!(step.op, Op::Addr { target, .. } if templates.contains(&target)))
      .find_map(|(at, _)| {
         steps[at.saturating_sub(ARG_REACH)..at]
            .iter()
            .rev()
            .find_map(|step| {
               match step.op {
                  Op::Offset { base, offset, .. }
                     if !frame.contains(&base) && FIELD.contains(&offset) =>
                  {
                     usize::try_from(offset).ok()
                  },
                  _ => None,
               }
            })
      })
}

/// `(rc, value)` from a head that loads `row.rc` and takes `value` past the
/// pointer within three instructions.
fn rc_deref(ix: &Index<'_>, steps: &[Step]) -> Option<(usize, usize)> {
   const HEAD: usize = 64;
   const NEXT: usize = 3;
   let frame = frame(ix, steps);
   let head = &steps[..steps.len().min(HEAD)];
   head.iter().enumerate().find_map(|(at, step)| {
      let Op::Load {
         reg,
         base,
         offset: rc,
         size: 8,
      } = step.op
      else {
         return None;
      };
      if frame.contains(&base) || !FIELD.contains(&rc) {
         return None;
      }
      let value = head[at + 1..head.len().min(at + 1 + NEXT)]
         .iter()
         .find_map(|next| {
            match next.op {
               Op::Offset { base, offset, .. } if base == reg && (1..0x40).contains(&offset) => {
                  Some(offset)
               },
               _ => None,
            }
         })?;
      Some((usize::try_from(rc).ok()?, usize::try_from(value).ok()?))
   })
}

/// `build_message_body(&MessageViewData, &mut config, ..)`, and where the
/// message keeps its id and the config its text colors.
#[derive(Clone, Debug)]
pub struct MessageBody {
   pub func:       usize,
   pub message_id: usize,
   pub colors:     BodyColors,
}

/// Where the body builder reads its text colors from the config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BodyColors {
   /// `&config.row_colors`, a block of `u32` colors.
   Block(usize),
   /// Each color's offset, picked as immediates three at a time by the
   /// message's state.
   Picks(Vec<usize>),
}

/// The function `render_row` calls that loads the `message-edited-` template.
///
/// Its head loads the id off the first argument, then either takes the
/// colors' address off the second or picks color offsets as runs of three
/// immediates.
pub fn message_body(ix: &Index<'_>, render_row: usize) -> Found<MessageBody> {
   const HEAD: usize = 0x60;
   const COLORS: Range<u64> = 0x100..0x400;
   let (message, config) = (
      ix.isa.arg(0).ok_or("no first argument register")?,
      ix.isa.arg(1).ok_or("no second argument register")?,
   );
   let func = ix
      .literal(b"\x0fmessage-edited-")
      .filter(|func| {
         func
            .callers()
            .iter()
            .any(|caller| caller.start == render_row)
      })
      .one("message body builder")?;
   let steps = func.steps();
   let head = &steps[..steps.len().min(HEAD)];

   let message_id = head
      .iter()
      .find_map(|step| {
         match step.op {
            Op::Load {
               base,
               offset,
               size: 8,
               ..
            } if base == message && (0x100..0x800).contains(&offset) => {
               usize::try_from(offset).ok()
            },
            _ => None,
         }
      })
      .ok_or("message body id load not found")?;

   let mut picks = head
      .windows(3)
      .filter_map(|run| {
         let values = run
            .iter()
            .map(|step| {
               match step.op {
                  Op::Imm { value, .. } if COLORS.contains(&value) => usize::try_from(value).ok(),
                  _ => None,
               }
            })
            .collect::<Option<Vec<_>>>()?;
         Some(values)
      })
      .flatten()
      .collect::<Vec<_>>();
   picks.sort_unstable();
   picks.dedup();
   let block = head.iter().find_map(|step| {
      match step.op {
         Op::Offset { base, offset, .. } if base == config => {
            u64::try_from(offset)
               .ok()
               .filter(|offset| COLORS.contains(offset))
               .and_then(|offset| usize::try_from(offset).ok())
         },
         _ => None,
      }
   });
   let colors = match (picks.len(), block) {
      (6.., _) => BodyColors::Picks(picks),
      (_, Some(block)) => BodyColors::Block(block),
      _ => return Err(format!("message body colors don't decode: {picks:x?}")),
   };
   Ok(MessageBody {
      func: func.start,
      message_id,
      colors,
   })
}
