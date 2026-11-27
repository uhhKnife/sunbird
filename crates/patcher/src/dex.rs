//! Forces Phoenix to launch. The launcher method that falls back to the React
//! Native client is found by its log string, since names are obfuscated per
//! build, and made to return true. Phoenix's host name table is found the
//! same way.

use std::collections::HashMap;

use pokedex::{
   bytecode::Operand,
   checksum::Checksums,
   dex::{
      Dex,
      Method,
   },
};

use crate::Error;

const ANCHOR: &str = "Phoenix didn't stay up for 3 launches";
/// One entry of the host name table, which no other code holds.
const TABLE_ANCHOR: &str = "Networking.request ";
/// The same entry in the table 357204 and later keep as lines.
const JOINED_ANCHOR: &str = "\nNetworking.request\n";
/// `const/4 v0, #1` then `return v0`.
const RETURN_TRUE: [u8; 4] = [0x12, 0x10, 0x0F, 0x00];
const CONST_STRING: u8 = 0x1A;
const CONST_STRING_JUMBO: u8 = 0x1B;
const FILLED_NEW_ARRAY: u8 = 0x24;
const FILLED_NEW_ARRAY_RANGE: u8 = 0x25;

/// The methods whose code loads a string `wanted` accepts.
fn loading(dex: &Dex, wanted: impl Fn(&str) -> bool) -> Result<Vec<Method<'_>>, Error> {
   let strings = dex.strings();
   let anchors = (0..strings.len())
      .filter(|&index| strings.get(index).is_some_and(&wanted))
      .collect::<Vec<_>>();
   let mut found = Vec::new();
   if anchors.is_empty() {
      return Ok(found);
   }

   for method in dex.methods() {
      for index in method.string_loads().map_err(Error::Parse)? {
         if anchors.contains(&index.map_err(Error::Parse)?) {
            found.push(method);
            break;
         }
      }
   }
   Ok(found)
}

/// Fills `numbers` from Phoenix's host name table, and fails when the table
/// gives one name two numbers.
///
/// Up to 357200 the method that builds the table loads one `"<name> <number>"`
/// string per entry. From 357204 it joins string constants, cut every 8000
/// bytes, in the order of a `filled-new-array`, and numbers the lines.
pub fn host_numbers(
   data: Vec<u8>,
   names: &[&str],
   numbers: &mut [Option<u16>],
) -> Result<(), Error> {
   let dex = Dex::parse(data).map_err(Error::Parse)?;
   let builders = loading(&dex, |text| text.starts_with(TABLE_ANCHOR))?;
   for method in &builders {
      for index in method.string_loads().map_err(Error::Parse)? {
         let Some(entry) = dex.strings().get(index.map_err(Error::Parse)?) else {
            continue;
         };
         if let Some((name, number)) = numbered(entry) {
            assign(names, numbers, name, number)?;
         }
      }
   }
   if !builders.is_empty() {
      return Ok(());
   }
   for method in loading(&dex, |text| text.contains(JOINED_ANCHOR))? {
      let Some(table) = joined_table(&dex, &method)? else {
         continue;
      };
      for (name, number) in joined(&table)? {
         assign(names, numbers, name, number)?;
      }
   }
   Ok(())
}

/// The table `method` joins: the strings of the first `filled-new-array` whose
/// registers all hold one and that holds the anchor, or the anchor string alone
/// when the method builds no array. An array that misses fails, since the
/// anchor string alone would number every later chunk wrong.
fn joined_table(dex: &Dex, method: &Method<'_>) -> Result<Option<String>, Error> {
   let strings = dex.strings();
   let Some(instructions) = method.instructions().map_err(Error::Parse)? else {
      return Ok(None);
   };
   let mut held = HashMap::new();
   let mut alone = None;
   let mut arrays = false;
   for instruction in &instructions {
      match (instruction.opcode(), instruction.operands()) {
         (
            CONST_STRING | CONST_STRING_JUMBO,
            [Operand::Registers(registers), Operand::String(index)],
         ) => {
            let Some(register) = registers.get(0) else {
               continue;
            };
            held.insert(register, *index);
            if let Some(text) = strings.get(*index)
               && text.contains(JOINED_ANCHOR)
            {
               alone.get_or_insert(text);
            }
         },
         (FILLED_NEW_ARRAY | FILLED_NEW_ARRAY_RANGE, [Operand::Registers(registers), ..]) => {
            arrays = true;
            let parts = registers
               .iter()
               .map(|register| held.get(&register).and_then(|&index| strings.get(index)))
               .collect::<Option<Vec<_>>>();
            if let Some(parts) = parts
               && parts.iter().any(|part| part.contains(JOINED_ANCHOR))
            {
               return Ok(Some(parts.concat()));
            }
         },
         _ => {},
      }
   }
   if arrays && alone.is_some() {
      return Err(Error::Dex(
         "host name table: no filled-new-array joins the anchor".into(),
      ));
   }
   Ok(alone.map(str::to_owned))
}

/// The name and number of a `"<name> <number>"` entry.
fn numbered(entry: &str) -> Option<(&str, u16)> {
   let (name, number) = entry.rsplit_once(' ')?;
   Some((name, number.parse().ok()?))
}

/// The names of a joined table with their numbers, which are their lines.
fn joined(table: &str) -> Result<Vec<(&str, u16)>, Error> {
   let lines = table.split('\n').collect::<Vec<_>>();
   if lines.len() > usize::from(u16::MAX) + 1 {
      return Err(Error::Dex(format!(
         "host name table has {} lines",
         lines.len()
      )));
   }
   Ok(lines
      .into_iter()
      .zip(0..=u16::MAX)
      .filter(|(name, _)| !name.is_empty())
      .collect())
}

fn assign(
   names: &[&str],
   numbers: &mut [Option<u16>],
   name: &str,
   number: u16,
) -> Result<(), Error> {
   for (wanted, slot) in names.iter().zip(numbers.iter_mut()) {
      if *wanted != name {
         continue;
      }
      match *slot {
         Some(seen) if seen != number => {
            return Err(Error::Dex(format!(
               "host name {wanted} is both {seen} and {number}"
            )));
         },
         _ => *slot = Some(number),
      }
   }
   Ok(())
}

/// Makes the launcher method return true, or `None` when this dex does not
/// hold it.
pub fn patch(data: Vec<u8>) -> Result<Option<Vec<u8>>, Error> {
   let dex = Dex::parse(data).map_err(Error::Parse)?;
   let methods = loading(&dex, |text| text.starts_with(ANCHOR))?;
   let method = match &methods[..] {
      [] => return Ok(None),
      [method] => method,
      _ => {
         return Err(Error::Dex(format!(
            "launcher anchor: expected one method, found {}",
            methods.len()
         )));
      },
   };
   let code = method
      .decode()
      .map_err(Error::Parse)?
      .ok_or_else(|| Error::Dex("launcher method has no code".into()))?;
   if !method.prototype().ends_with(")Z") || code.registers() < 1 {
      return Err(Error::Dex(format!(
         "launcher method is {} with {} registers",
         method.prototype(),
         code.registers()
      )));
   }
   let insns = code.instructions_range().start;

   let mut data = dex.into_bytes();
   data
      .get_mut(insns..insns + RETURN_TRUE.len())
      .ok_or(Error::Truncated)?
      .copy_from_slice(&RETURN_TRUE);
   Checksums::rehash(&mut data).map_err(Error::Parse)?;
   Ok(Some(data))
}

#[cfg(test)]
mod tests {
   use super::{
      joined,
      numbered,
   };

   #[test]
   fn numbers_one_string_tables_by_line() {
      let table = "-\nAccess\nNetworking.cancel\nNetworking.request\n";
      assert_eq!(joined(table).unwrap(), [
         ("-", 0),
         ("Access", 1),
         ("Networking.cancel", 2),
         ("Networking.request", 3),
      ]);
   }

   #[test]
   fn reads_numbered_entries() {
      assert_eq!(
         numbered("Networking.request 168"),
         Some(("Networking.request", 168))
      );
      assert_eq!(numbered("Networking.request"), None);
      assert_eq!(numbered("label x"), None);
   }
}
