//! Freezes every built-in the plugins share, so one plugin cannot swap
//! `String.prototype.replace` or `Promise.prototype.then` to read what another
//! passes through them, and freezes `globalThis` so none can leave anything for
//! another to pick up.

use rquickjs::{
   Array,
   CatchResultExt,
   Ctx,
   Function,
   Object,
   Value,
};

/// Built-ins no property path from `globalThis` reaches. An expression a build
/// of `QuickJS` cannot evaluate names a feature it lacks, and is skipped.
const HIDDEN: [&str; 12] = [
   "Object.getPrototypeOf(function* () {})",
   "Object.getPrototypeOf(async function () {})",
   "Object.getPrototypeOf(async function* () {})",
   "Object.getPrototypeOf(Int8Array)",
   "Object.getPrototypeOf([][Symbol.iterator]())",
   "Object.getPrototypeOf(new Map()[Symbol.iterator]())",
   "Object.getPrototypeOf(new Set()[Symbol.iterator]())",
   "Object.getPrototypeOf(''[Symbol.iterator]())",
   "Object.getPrototypeOf(''.matchAll(/a/g))",
   "Object.getPrototypeOf([].values().map((x) => x))",
   "Object.getPrototypeOf(Iterator.from({ next() {} }))",
   "(function () { 'use strict'; return Object.getOwnPropertyDescriptor(arguments, 'callee').get; \
    })()",
];

/// Inherited properties that code assigns on its own objects, like
/// `this.name = "MyError"` in an `Error` subclass. Frozen as data, an
/// assignment would throw, so each becomes an accessor whose setter defines the
/// property on the object assigned to.
const ASSIGNED: [(&str, &[&str]); 12] = [
   ("Object", &[
      "constructor",
      "toString",
      "valueOf",
      "toLocaleString",
      "hasOwnProperty",
   ]),
   ("Function", &[
      "constructor",
      "toString",
      "call",
      "apply",
      "bind",
   ]),
   ("Array", &["constructor", "toString", "push"]),
   ("Promise", &["constructor"]),
   ("Error", &["constructor", "name", "message", "toString"]),
   ("EvalError", &["constructor", "name", "message"]),
   ("RangeError", &["constructor", "name", "message"]),
   ("ReferenceError", &["constructor", "name", "message"]),
   ("SyntaxError", &["constructor", "name", "message"]),
   ("TypeError", &["constructor", "name", "message"]),
   ("URIError", &["constructor", "name", "message"]),
   ("AggregateError", &["constructor", "name", "message"]),
];

/// Builds the accessor in JS, since a Rust closure holding the prototype would
/// keep it alive past the runtime's last collection, which `QuickJS` asserts
/// on.
const ACCESSOR: &str = "(define, home, key, original) => ({
   get() { return original; },
   set(value) {
      if (this === home || Object(this) !== this) throw new TypeError(`'${key}' is read-only`);
      define(this, key, { value, writable: true, enumerable: true, configurable: true });
   },
})";

fn settable<'js>(ctx: &Ctx<'js>, define: &Function<'js>) -> rquickjs::Result<()> {
   let accessor = ctx.eval::<Function<'js>, _>(ACCESSOR)?;
   for (name, keys) in ASSIGNED {
      let Some(prototype) = ctx
         .globals()
         .get::<_, Option<Object<'js>>>(name)?
         .map(|constructor| constructor.get::<_, Object<'js>>("prototype"))
         .transpose()?
      else {
         continue;
      };
      for &key in keys {
         let original = prototype.get::<_, Value<'js>>(key)?;
         let descriptor =
            accessor.call::<_, Object<'js>>((define.clone(), prototype.clone(), key, original))?;
         define.call::<_, Value<'js>>((prototype.clone(), key, descriptor))?;
      }
   }
   Ok(())
}

/// Freezes everything reachable from `globalThis`, the [`HIDDEN`] built-ins
/// and `extra`, through properties, accessors and prototypes.
pub fn lockdown<'js>(ctx: &Ctx<'js>, extra: Vec<Value<'js>>) -> rquickjs::Result<()> {
   let object = ctx.globals().get::<_, Object>("Object")?;
   let freeze = object.get::<_, Function>("freeze")?;
   let frozen = object.get::<_, Function>("isFrozen")?;
   let descriptor = object.get::<_, Function>("getOwnPropertyDescriptor")?;
   let prototype = object.get::<_, Function>("getPrototypeOf")?;
   settable(ctx, &object.get::<_, Function>("defineProperty")?)?;
   let own_keys = ctx
      .globals()
      .get::<_, Object>("Reflect")?
      .get::<_, Function>("ownKeys")?;

   let mut pending = extra;
   pending.push(ctx.globals().into_value());
   for hidden in HIDDEN {
      if let Ok(value) = ctx.eval::<Value<'js>, _>(hidden).catch(ctx) {
         pending.push(value);
      }
   }
   while let Some(value) = pending.pop() {
      if !value.is_object() || frozen.call::<_, bool>((value.clone(),))? {
         continue;
      }
      freeze.call::<_, Value<'js>>((value.clone(),))?;
      pending.push(prototype.call((value.clone(),))?);
      for key in own_keys
         .call::<_, Array<'js>>((value.clone(),))?
         .iter::<Value<'js>>()
      {
         let Some(found) = descriptor
            .call::<_, Value<'js>>((value.clone(), key?))?
            .into_object()
         else {
            continue;
         };
         for field in ["value", "get", "set"] {
            pending.push(found.get(field)?);
         }
      }
   }
   Ok(())
}
