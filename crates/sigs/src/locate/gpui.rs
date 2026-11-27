//! [`Gpui`], Discord's GPUI and Mana builders, from the Developer Mode switch
//! row (`set-devmode`) and the `TesterUpdates` sign-in button, which call them
//! in a fixed order on every desktop build.

use std::collections::HashMap;

use crate::{
   Found,
   desktop::Gpui,
   index::{
      Func,
      Index,
      Op,
   },
};

/// Drop glue and clone thunks run this short. The builders run 88 bytes
/// and more.
const GLUE: usize = 32;

/// How far into a merged literal blob a function's other keys sit.
const BLOB: usize = 0x400;

/// How many functions after `div_child_div` its `SharedString` sibling may sit.
const NEIGHBOURS: usize = 6;

/// The function loading `needle`'s literal, the load's site, and the literal.
fn anchored<'ix>(ix: &'ix Index<'ix>, needle: &[u8]) -> Found<(Func<'ix>, usize, usize)> {
   let what = String::from_utf8_lossy(needle);
   let func = ix.literal(needle).one(&what)?;
   let hit = crate::one(&what, &ix.text(needle))?;
   let site = ix
      .loads_of(hit..hit + 1)
      .into_iter()
      .map(|(site, _)| site)
      .find(|site| (func.start..func.end).contains(site))
      .ok_or_else(|| format!("{what} load not found"))?;
   Ok((func, site, hit))
}

/// The builders, read off the order of calls.
///
/// - `div_new` is `#[track_caller]`, so its call before the row's literal loads
///   a `Location`, and `flex` and `flex_col` follow it.
/// - Past `Switch::new`, the i18n lookups pass keys from the page's literal
///   blob and glue is short. The four calls left are the setters.
/// - `ActionRow` opens with `div_new` and `flex`. Its two blocks each end in
///   `div_child_div`, the first with the text column three calls before.
/// - `div_style_mut` is the first call most style setters make.
/// - `<SharedString as IntoElement>::into_any_element`, a callee of a neighbour
///   of `div_child_div`, drops its string by comparing the tag with 0xff
///   (`None`) and then 0x19 (`Arc`).
#[expect(clippy::too_many_lines, reason = "one block per builder")]
pub fn gpui(ix: &Index<'_>) -> Found<Gpui> {
   let (page, anchor, hit) = anchored(ix, b"set-devmodeDeveloper Mode")?;
   let steps = page.steps();
   let calls = page.calls_at();
   let gap_loads = |at: usize| {
      let previous = calls
         .iter()
         .map(|&(site, _)| site)
         .take_while(|&site| site < at)
         .last()
         .unwrap_or(page.start);
      steps
         .iter()
         .filter(move |step| (previous..at).contains(&step.at))
         .filter_map(|step| pick_addr(step.op))
   };
   let split = calls.partition_point(|&(site, _)| site < anchor);
   let (before, after) = calls.split_at(split);

   let (new_at, caller_loc) = before
      .iter()
      .enumerate()
      .rev()
      .find_map(|(at, &(site, _))| {
         gap_loads(site)
            .find(|&target| ix.location_at(target).is_some())
            .map(|loc| (at, loc))
      })
      .ok_or("div_new Location not found")?;
   let [(_, div_new), (_, div_flex), (_, div_flex_col), ..] = before[new_at..] else {
      return Err("Developer Mode row has no flex column before it".to_owned());
   };

   let &[(_, switch_new), ref rest @ ..] = after else {
      return Err("Developer Mode row makes no calls".to_owned());
   };
   let setters = rest
      .iter()
      .filter(|&&(site, callee)| {
         ix.function(callee).is_some_and(|func| func.size() > GLUE)
            && !gap_loads(site).any(|target| (hit..hit + BLOB).contains(&target))
      })
      .map(|&(_, callee)| callee)
      .collect::<Vec<usize>>();
   let [
      switch_label,
      switch_desc,
      switch_on_change,
      switch_into_div,
      ..,
   ] = setters[..]
   else {
      return Err(format!("{} Developer Mode row setters", setters.len()));
   };
   let alloc_or_oom = *ix
      .func(switch_on_change)?
      .calls()
      .first()
      .ok_or("alloc_or_oom not found in Switch::on_change")?;

   let (tester, anchor, _) = anchored(ix, b"tester-updates-sign-in")?;
   let after_btn = tester
      .calls_at()
      .into_iter()
      .filter(|&(site, _)| site > anchor)
      .map(|(_, callee)| callee)
      .collect::<Vec<usize>>();
   let button_new = *after_btn.first().ok_or("Button::new not found")?;
   let opens_row = |callee: usize| {
      ix.func(callee).is_ok_and(|func| {
         let inner = func.calls();
         inner.first() == Some(&div_new) && inner.iter().take(4).any(|&call| call == div_flex)
      })
   };
   let row_at = after_btn
      .iter()
      .skip(1)
      .position(|&callee| opens_row(callee))
      .ok_or("ActionRow no longer calls div_new and flex first")?
      + 1;
   let action_row = after_btn[row_at];
   let button_on_click = *after_btn[..row_at]
      .iter()
      .rfind(|&&callee| ix.function(callee).is_some_and(|func| func.size() > GLUE))
      .ok_or("Button::on_click not found before ActionRow")?;
   let div_into_any = *after_btn
      .get(row_at + 1)
      .ok_or("Div::into_any_element not found after ActionRow")?;

   let row = ix.func(action_row)?.calls();
   let second = row[1..]
      .iter()
      .position(|&callee| callee == div_new)
      .ok_or("ActionRow builds one Div")?
      + 1;
   if second < 4 {
      return Err("ActionRow's text column moved".to_owned());
   }
   let div_child_div = row[second - 1];
   let text_block = row[second - 4];
   let last_child = row
      .iter()
      .rposition(|&callee| callee == div_child_div)
      .filter(|&at| at > second + 1)
      .ok_or("ActionRow no longer adds its children with div_child_div")?;
   let div_child_button = row[last_child - 1];

   let mut firsts = HashMap::<usize, usize>::new();
   for &callee in row[..second].iter().filter(|&&callee| callee != div_new) {
      if let Some(&first) = ix.func(callee)?.calls().first() {
         *firsts.entry(first).or_default() += 1;
      }
   }
   let mut ranked = firsts
      .into_iter()
      .map(|(first, count)| (count, first))
      .collect::<Vec<(usize, usize)>>();
   ranked.sort_unstable_by(|a, b| b.cmp(a));
   let div_style_mut = match ranked[..] {
      [(top, first), (next, _), ..] if top >= 2 && top > next => first,
      [(top, first)] if top >= 2 => first,
      _ => return Err(format!("div_style_mut has no clear winner in {ranked:x?}")),
   };

   let child = ix.func(div_child_div)?;
   let div_push_any = child.calls().get(1).copied();
   let drops_string = |callee: usize| {
      ix.func(callee).is_ok_and(|func| {
         let steps = func.steps();
         steps.iter().enumerate().any(|(at, step)| {
            matches!(step.op, Op::Cmp { value: 0xFF, .. })
               && steps[at + 1..]
                  .iter()
                  .take(2)
                  .any(|next| matches!(next.op, Op::Cmp { value: 0x19, .. }))
         })
      })
   };
   let str_into_any = std::iter::successors(Some(child), Func::next)
      .take(NEIGHBOURS + 1)
      .find_map(|func| {
         func
            .calls()
            .into_iter()
            .find(|&callee| drops_string(callee))
      });

   Ok(Gpui {
      caller_loc,
      div_new,
      div_flex,
      div_flex_col,
      div_style_mut,
      div_child_div,
      div_child_button,
      div_into_any,
      div_push_any,
      str_into_any,
      text_block,
      switch_new,
      switch_into_div,
      button_new,
      action_row,
      alloc_or_oom,
      switch_label,
      switch_desc,
      switch_on_change,
      button_on_click,
   })
}

const fn pick_addr(op: Op) -> Option<usize> {
   match op {
      Op::Addr { target, .. } => Some(target),
      _ => None,
   }
}
