//! `sigscan <library.so | Discord.exe | Discord.app/Contents/MacOS/Discord>
//! [command]`
//!
//! Loads an ELF or PE64 binary the way the OS loader maps it and dumps the
//! gateway registry the runtime would hook. On x86-64 files it also finds
//! code for you:
//!
//! - `strings <text>`: where `text` sits, the code that loads it, and the
//!   function around each load.
//! - `scan <pattern>`: where a byte pattern like `48 8D ?? 05` matches in code.
//! - `refs <addr>`: the code and pointers that reference `addr`.
//! - `check`: runs every locator the runtime uses on this file's platform and
//!   exits 1 if any misses, so a new Discord build can be vetted before
//!   shipping against it.
//! - `dis <addr> [count]`: the bounds of the function holding `addr`, and
//!   `count` instructions from `addr` to that function's end.
//!
//! Addresses are hex at the file's preferred base. One below the base is an
//! RVA. Every address printed carries its RVA too, for a live process's base.

use std::{
   collections::HashMap,
   env,
   fs,
};

use misstep::{
   OptionExt,
   ResultExt,
};
use phoenix_hook::{
   arm64,
   image::Image,
   pattern::Pattern,
   x86,
};
use phoenix_sigs::{
   Found,
   desktop,
   file::{
      BinaryFile,
      Machine,
   },
   gateway_send::DesktopGatewaySend,
   http::DesktopHttpTransport,
   index::{
      Index,
      Isa,
   },
   ios,
   locate::{
      self,
      Family,
      LOCATORS,
   },
   registry::GatewayRegistry,
};

const USAGE: &str = "usage: sigscan <library.so | Discord.exe | Discord | PhoenixFatClient | \
                     main.jsbundle> [check | strings <text> | refs <addr> | dis <addr> [count] | \
                     explain <addr> | ops <addr> [count] | source <path suffix>]";

fn main() -> misstep::Result<()> {
   misstep::install_panic_hook();
   let args = env::args().skip(1).collect::<Vec<String>>();
   let path = args.first().context(USAGE)?;
   let data = fs::read(path).with_context(|| format!("reading {path}"))?;
   if data.starts_with(&ios::HERMES_MAGIC) {
      let switch = ios::switch_entrypoint(&data).map_err(misstep::Report::msg)?;
      println!(
         "ok    {:<20} {:#x}",
         "switch entrypoint", switch.default_config
      );
      return Ok(());
   }
   let parsed = BinaryFile::parse(path, &data)?;
   let image = parsed.image();
   let base = image.pdata.map_or(0, |(base, ..)| base);
   let addr = |at: usize| -> misstep::Result<usize> {
      let text = args.get(at).context(USAGE)?;
      let value = usize::from_str_radix(text.trim_start_matches("0x"), 16)
         .with_context(|| format!("{text} is not a hex address"))?;
      Ok(if value < base { base + value } else { value })
   };
   let tools = Tools {
      image,
      base,
      arm64: parsed.machine() == Machine::Aarch64,
   };
   match args.get(1).map(String::as_str) {
      None => dump(image),
      Some("check") => {
         let macho = matches!(parsed, BinaryFile::MachO(_));
         let family = if parsed.machine() == Machine::X86_64
            || macho && !image.find_bytes(MACOS_DESKTOP).is_empty()
         {
            Family::Desktop
         } else {
            Family::Mobile
         };
         let ix = Index::new(image, isa_of(image, parsed.machine()));
         check(image, &ix, family, parsed.machine(), macho)
      },
      Some("ops") => {
         let ix = Index::new(image, isa_of(image, parsed.machine()));
         let at = addr(2)?;
         let count = args
            .get(3)
            .map_or(Ok(24), |count| count.parse::<usize>())
            .context(USAGE)?;
         let end = ix.function(at).map_or(at + count * 4, |func| func.end);
         for step in phoenix_sigs::index::op::decode(image, ix.isa, at, end)
            .iter()
            .take(count)
         {
            println!("{:#x}  {:?}", step.at, step.op);
         }
         Ok(())
      },
      Some("source") => {
         let ix = Index::new(image, isa_of(image, parsed.machine()));
         for func in ix.source(args.get(2).context(USAGE)?) {
            let callees = func
               .calls()
               .iter()
               .map(|at| format!("{at:#x}"))
               .collect::<Vec<String>>();
            println!(
               "{func:?} {} bytes, {} callers, calls {}",
               func.size(),
               func.callers().len(),
               callees.join(" ")
            );
         }
         Ok(())
      },
      Some("explain") => {
         let ix = Index::new(image, isa_of(image, parsed.machine()));
         explain(&ix, addr(2)?, base);
         Ok(())
      },
      Some("strings") => tools.strings(args.get(2).context(USAGE)?),
      Some("scan") => tools.scan(&args[2..].join(" ")),
      Some("refs") => {
         tools.refs(addr(2)?);
         Ok(())
      },
      Some("dis") => {
         let count = args
            .get(3)
            .map_or(Ok(40), |count| count.parse::<usize>())
            .context(USAGE)?;
         tools.dis(addr(2)?, count);
         Ok(())
      },
      Some("flat") if tools.arm64 => {
         let from = addr(2)?;
         let to = args.get(3).map_or(Ok(from + 0x400), |_| addr(3))?;
         tools.flat(from, to);
         Ok(())
      },
      Some(_) => Err(misstep::Report::msg(USAGE)),
   }
}

const fn isa_of(image: &Image<'_>, machine: Machine) -> Isa {
   match machine {
      Machine::X86_64 => {
         Isa::X86_64 {
            win64: image.pdata.is_some(),
         }
      },
      Machine::Aarch64 => Isa::Aarch64,
      Machine::Arm => Isa::Thumb2,
   }
}

/// What the function holding `addr` is reachable from: the panic locations,
/// literals and callsites it loads, and its callers and callees.
fn explain(ix: &Index<'_>, addr: usize, base: usize) {
   let Some(func) = ix.function(addr) else {
      println!("{addr:#x} is in no function");
      return;
   };
   let locations = ix
      .locations()
      .map(|loc| {
         (
            loc.file.slot,
            format!("{}:{}", ix.str_of(loc.file), loc.line),
         )
      })
      .collect::<HashMap<usize, String>>();
   let describe = |target: usize| -> String {
      if let Some(location) = locations.get(&target) {
         return format!("panic {location}");
      }
      let bytes = ix.image.read(target, 48).unwrap_or_default();
      let text = bytes
         .iter()
         .take_while(|byte| byte.is_ascii_graphic() || **byte == b' ')
         .map(|&byte| char::from(byte))
         .collect::<String>();
      if text.len() >= 4 {
         format!("str {text:?}")
      } else if ix.image.is_code(target) {
         "code".to_owned()
      } else {
         "data".to_owned()
      }
   };
   let rva = |at: usize| at.wrapping_sub(base);
   let callers = func.callers();
   println!(
      "{:#x} (+{:#x}), {} bytes, {} callers, {} calls",
      func.start,
      rva(func.start),
      func.size(),
      callers.len(),
      func.calls().len(),
   );
   for caller in callers.iter().take(8) {
      println!("  caller {:#x}, {} bytes", caller.start, caller.size());
   }
   for target in func.loads() {
      println!("  loads {target:#x} {}", describe(target));
   }
   for callee in func.calls() {
      let size = ix.function(callee).map_or(0, |callee| callee.size());
      println!("  calls {callee:#x}, {size} bytes");
   }
}

/// A string only the desktop clients carry, which tells macOS Phoenix from
/// iOS's `PhoenixFatClient`; both are arm64 Mach-O.
const MACOS_DESKTOP: &[u8] = b"DESKTOP_ACCESS_GATE_TITLE";

/// Runs every locator for `machine` and prints what each found.
#[expect(clippy::too_many_lines, reason = "one report per locator")]
fn check(
   image: &Image<'_>,
   ix: &Index<'_>,
   family: Family,
   machine: Machine,
   macho: bool,
) -> misstep::Result<()> {
   let mut missed = 0;
   let mut report = |name: &str, found: Found<String>| {
      match found {
         Ok(detail) => println!("ok    {name:<20} {detail}"),
         Err(why) => {
            missed += 1;
            println!("MISS  {name:<20} {why}");
         },
      }
   };
   let at = |addr: usize| format!("{addr:#x}");
   let registry = GatewayRegistry::locate(image).map_err(|err| err.to_string());
   report(
      "gateway registry",
      registry
         .as_ref()
         .map(|registry| format!("{} events", registry.iter().count()))
         .map_err(Clone::clone),
   );
   match machine {
      Machine::X86_64 => {
         let abi = x86::Abi::of(image);
         if abi == x86::Abi::Win64 {
            report(
               "Windows restart",
               desktop::windows_restart_script(image).map(at),
            );
         }
         let prologues = desktop::Prologues::of(abi);
         let http = DesktopHttpTransport::locate(image);
         report(
            "http transport",
            http.as_ref().map_err(Clone::clone).and_then(|http| {
               prologues
                  .frame
                  .at(image, http.send_fn)
                  .then(|| format!("{} request {:x?}", at(http.send_fn), http.request))
                  .ok_or_else(|| "send prologue changed".to_owned())
            }),
         );
         report(
            "http responses",
            http.as_ref().map_err(Clone::clone).and_then(|http| {
               http
                  .response
                  .clone()
                  .map(|layout| format!("{} {layout:x?}", at(http.poll_fn)))
            }),
         );
         report(
            "gateway send",
            DesktopGatewaySend::locate(image).map(|gw| {
               format!(
                  "{} ({} slots, ok {:#x})",
                  at(gw.start_send_fn),
                  gw.start_send_slots.len(),
                  gw.ok_tag
               )
            }),
         );
         report(
            "host allocator",
            match http
               .as_ref()
               .ok()
               .map(|http| (http.host_alloc, http.host_dealloc))
            {
               Some((Some(alloc), Some(dealloc))) => {
                  Ok(format!("alloc {}, dealloc {}", at(alloc), at(dealloc)))
               },
               Some((alloc, dealloc)) => {
                  Err(format!(
                     "alloc {}, dealloc {}",
                     alloc.map_or_else(|| "missing".to_owned(), at),
                     dealloc.map_or_else(|| "missing".to_owned(), at)
                  ))
               },
               None => Err("no http transport".to_owned()),
            },
         );
         report("settings layer", desktop::settings_layer(image).map(at));
         report("animation frame", desktop::animation_frame(image).map(at));
         report("notification gate", desktop::notification_gate(image).map(at));
         if abi == x86::Abi::SysV {
            report(
               "wayland frame",
               desktop::wayland_frame(image).map(|found| {
                  format!(
                     "{} (force_render +{:#x}, ping {})",
                     at(found.frame),
                     found.force_render,
                     at(found.ping)
                  )
               }),
            );
            report(
               "va scaler lookup",
               desktop::va_scaler_lookup(image).map(|skip| at(skip.at)),
            );
            report(
               "linux primary display",
               desktop::linux_primary_display(image).map(|found| {
                  format!(
                     "{} (displays {})",
                     at(found.primary_display),
                     at(found.displays)
                  )
               }),
            );
         }
         let gpui = locate::gpui::gpui(ix);
         let layouts = gpui
            .as_ref()
            .map_err(|_| "needs the builders".to_owned())
            .and_then(|gpui| desktop::gpui_layouts(image, gpui));
         report(
            "gpui layouts",
            layouts
               .as_ref()
               .map(|l| format!("{:x?} {:x?} {:x?}", l.div, l.switch, l.button))
               .map_err(Clone::clone),
         );
         report(
            "style offsets",
            layouts
               .as_ref()
               .map(|l| format!("{:x?}", l.style))
               .map_err(|_| "needs the layouts".to_owned()),
         );
         report(
            "member row",
            desktop::member_row(image).map(|row| {
               let closure = match row.name.closure_slot {
                  Some(slot) => format!("frame +{slot:#x}"),
                  None => format!("closure in {}", row.name.frame),
               };
               format!(
                  "{} (name calls {:x?}, {closure}, env +{:#x})",
                  at(row.func),
                  row.name.sites,
                  row.name.env
               )
            }),
         );
         report(
            "dm row",
            desktop::dm_row(image).map(|row| {
               format!(
                  "{} (name call {}, recipient [{frame}+{:#x}] if [{frame}+{:#x}])",
                  at(row.func),
                  at(row.site),
                  row.user,
                  row.some,
                  frame = row.frame
               )
            }),
         );
         report(
            "svg builders",
            desktop::svg_builders(image).map(|svg| format!("{svg:x?}")),
         );
         report("asset loader", desktop::asset_load(image).map(at));
         let row = locate::message::message_row(ix);
         report(
            "menu submenu",
            desktop::submenu_layout(image).map(|layout| format!("{layout:x?}")),
         );
         report(
            "sticker check",
            desktop::sticker_check(image).map(at),
         );
         report(
            "message context menu",
            desktop::message_context_menu(image).map(|menu| {
               format!(
                  "{} (msg +{:#x}, id +{:#x}, ch +{:#x}) {:x?}",
                  at(menu.build_fn),
                  menu.msg_ptr_offset,
                  menu.msg_id_offset,
                  menu.channel_id_offset,
                  menu.layout,
               )
            }),
         );
         report(
            "native modal",
            gpui
               .as_ref()
               .map_err(|_| "needs the builders".to_owned())
               .and_then(|gpui| {
                  let layouts = layouts
                     .as_ref()
                     .map_err(|_| "needs the layouts".to_owned())?;
                  desktop::modal(image, gpui.div_into_any, &layouts.div)
               })
               .map(|m| {
                  format!(
                     "overlay={}, push={}, new={}, into_any={}, div_id={}, val=+{:#x}, \
                      mouse_down=+{:#x}, listener_push={}, is_hovered={}, propagate=+{:#x} {:x?}",
                     at(m.overlay_render),
                     at(m.vec_push_any),
                     at(m.modal_new),
                     at(m.modal_into_any),
                     at(m.div_id),
                     m.window_validation_offset,
                     m.dismiss.mouse_down_listeners,
                     at(m.dismiss.listener_push),
                     at(m.dismiss.hitbox_is_hovered),
                     m.dismiss.propagate_event,
                     m.layout,
                  )
               }),
         );
         report(
            "native text fields",
            desktop::text_fields(image).map(|tf| {
               format!(
                  "single={}, multi={}, ti={}, ta={}, get={}, set={} {:x?}",
                  at(tf.cx_new_single),
                  at(tf.cx_new_multiline),
                  at(tf.text_input_new),
                  at(tf.text_area_new),
                  at(tf.text_get),
                  at(tf.set_value),
                  tf.layout,
               )
            }),
         );
         report("composer gift", desktop::composer_gift(image).map(at));
         if abi == x86::Abi::Win64 {
            report(
               "ready text",
               registry
                  .as_ref()
                  .map_err(|_| "needs the registry".to_owned())
                  .and_then(|registry| {
                     let id = registry.id("READY").ok_or("no READY")?;
                     desktop::ready_parse(image, registry.entry(id).handler)
                        .and_then(|parse| desktop::ready_text(image, parse))
                  })
                  .map(at),
            );
            report(
               "ready session",
               registry
                  .as_ref()
                  .map_err(|_| "needs the registry".to_owned())
                  .and_then(|registry| {
                     let id = registry.id("READY").ok_or("no READY")?;
                     desktop::ready_parse(image, registry.entry(id).handler)
                        .and_then(|parse| desktop::ready_session(image, parse))
                  })
                  .map(|session| {
                     format!(
                        "{} (kind +{:#x} = {}, raw +{:#x})",
                        at(session.func),
                        session.kind,
                        session.raw_kind,
                        session.raw
                     )
                  }),
            );
            report(
               "channel toolbar",
               desktop::channel_toolbar(image).map(|toolbar| {
                  format!(
                     "button {}, append {}, sizes {:#x}/{:#x}, click +{:#x}",
                     at(toolbar.button_site),
                     at(toolbar.append_site),
                     toolbar.button_size,
                     toolbar.toolbar_size,
                     toolbar.on_click,
                  )
               }),
            );
            report(
               "channel sidebar",
               desktop::channel_sidebar(image).map(|sidebar| {
                  format!(
                     "column {}, publish {}, rail {}, handle {}",
                     at(sidebar.column_site),
                     at(sidebar.publish_site),
                     at(sidebar.rail),
                     at(sidebar.handle_site),
                  )
               }),
            );
            report(
               "scene draw",
               desktop::scene_draw(image).map(|found| {
                  format!(
                     "{} quads +{:#x}, mono +{:#x}, subpixel +{:#x}",
                     at(found.draw),
                     found.quads,
                     found.mono,
                     found.subpixel
                  )
               }),
            );
         }
         let pending = desktop::pending_counts(image);
         let moved = |func: usize| {
            desktop::hook_point(image, func).map(|point| {
               match point {
                  desktop::HookPoint::Entry(prologue) => {
                     format!("{} ({} bytes moved)", at(func), prologue.len)
                  },
                  desktop::HookPoint::Slots(slots) => {
                     format!("{} (through slots {slots:x?})", at(func))
                  },
               }
            })
         };
         report(
            "pending counts",
            pending.as_ref().map_err(Clone::clone).and_then(|found| {
               let badges = found
                  .badges
                  .iter()
                  .map(|&badge| moved(badge))
                  .collect::<Found<Vec<String>>>()?;
               Ok(format!(
                  "badges {}, friend requests {}",
                  badges.join(", "),
                  moved(found.friend_requests)?
               ))
            }),
         );
         let friend_requests = pending
            .as_ref()
            .map(|found| found.friend_requests)
            .map_err(|_| "needs the pending counts".to_owned());
         report(
            "home count",
            friend_requests
               .clone()
               .and_then(|func| desktop::home_count(image, func))
               .and_then(moved),
         );
         report(
            "home badge",
            friend_requests
               .and_then(|func| desktop::home_badge(image, func))
               .and_then(moved),
         );
         let json = desktop::message_json(image);
         report(
            "stream quality",
            desktop::stream_quality(image).and_then(|func| {
               prologues
                  .stream_quality
                  .is_none_or(|prologue| prologue.at(image, func))
                  .then(|| at(func))
                  .ok_or_else(|| "prologue changed".to_owned())
            }),
         );
         report(
            "premium feature",
            desktop::premium_feature(image).and_then(|found| {
               prologues
                  .premium_feature
                  .is_none_or(|prologue| prologue.at(image, found.func))
                  .then(|| {
                     let appearance = found.app_icons.map_or_else(
                        || "app_icons=off (tier lists changed)".to_owned(),
                        |id| format!("app_icons={id:#x}"),
                     );
                     format!(
                        "{} stream_high={:#x} {appearance}",
                        at(found.func),
                        found.stream_high
                     )
                  })
                  .ok_or_else(|| "prologue changed".to_owned())
            }),
         );
         report(
            "theme perk",
            desktop::theme_perk(image)
               .map(|perk| format!("{} field +{:#x}", at(perk.accessor), perk.field)),
         );
         report(
            "message json",
            json
               .as_ref()
               .map(|found| {
                  format!(
                     "to_value {}, drop {}",
                     at(found.to_value),
                     at(found.drop_value)
                  )
               })
               .map_err(Clone::clone),
         );
         report(
            "message header",
            row.as_ref()
               .map_err(|_| "needs the message row".to_owned())
               .and_then(|row| locate::message::message_body(ix, row.func))
               .and_then(|body| desktop::message_header(image, body.func))
               .map(|header| {
                  let sites = header
                     .sites
                     .iter()
                     .map(|site| format!("{} [{}+{:#x}]", at(site.site), header.frame, site.slot))
                     .collect::<Vec<_>>()
                     .join(", ");
                  format!(
                     "name calls {sites}; child_node {}, svg_new {}, push_svg {}, leaf {:#x} \
                      (color +{:#x})",
                     at(header.child_node),
                     at(header.svg.new),
                     at(header.svg.push),
                     header.svg.size,
                     header.svg.color
                  )
               }),
         );
      },
      // macOS Phoenix, the desktop client built for arm64.
      Machine::Aarch64 if macho && !image.find_bytes(MACOS_DESKTOP).is_empty() => {
         report(
            "malloc re-exec",
            image
               .find_bytes(phoenix_sigs::MACOS_REEXEC.as_bytes())
               .first()
               .map(|&found| at(found))
               .ok_or_else(|| "the loader waits for a re-exec this build never does".to_owned()),
         );
         report(
            "malloc settings",
            image
               .find_bytes(phoenix_sigs::MACOS_MALLOC.as_bytes())
               .first()
               .map(|&found| at(found))
               .ok_or_else(|| "the loader can't tell a launch that never re-execs".to_owned()),
         );
         let http = phoenix_sigs::macos::http_transport(image);
         report(
            "http transport",
            http.as_ref().map_err(Clone::clone).map(|http| {
               format!(
                  "send {} ({} slots), poll {} ({} slots), request {:x?}",
                  at(http.send_fn),
                  http.send_slots.len(),
                  at(http.poll_fn),
                  http.poll_slots.len(),
                  http.request
               )
            }),
         );
         report(
            "http responses",
            http.as_ref().map_err(Clone::clone).and_then(|http| {
               http
                  .response
                  .clone()
                  .map(|layout| format!("{} {layout:x?}", at(http.poll_fn)))
            }),
         );
         report(
            "gateway send",
            phoenix_sigs::macos::gateway_send(image).map(|gw| {
               format!(
                  "{} ({} slots, ok {:#x})",
                  at(gw.start_send_fn),
                  gw.start_send_slots.len(),
                  gw.ok_tag
               )
            }),
         );
         report(
            "composer gift",
            phoenix_sigs::macos::composer_gift(image).map(|gift| {
               format!(
                  "{} (shown {:#010x}, hidden {:#010x})",
                  at(gift.site),
                  gift.shown,
                  gift.hidden
               )
            }),
         );
         report(
            "message context menu",
            phoenix_sigs::macos::message_context_menu(image).map(|menu| format!("{menu:x?}")),
         );
         let gpui = locate::gpui::gpui(ix);
         report(
            "host allocator",
            gpui
               .as_ref()
               .map_err(|_| "needs gpui builders".to_owned())
               .and_then(|gpui| phoenix_sigs::macos::host_allocator(image, gpui.alloc_or_oom))
               .map(|(alloc, dealloc)| format!("alloc {}, dealloc {}", at(alloc), at(dealloc))),
         );
         let gpui_layout = gpui
            .as_ref()
            .map_err(|_| "needs gpui builders".to_owned())
            .and_then(|gpui| phoenix_sigs::macos::gpui_layouts(image, gpui));
         report(
            "gpui layouts",
            gpui_layout
               .as_ref()
               .map(|layout| format!("{layout:x?}"))
               .map_err(Clone::clone),
         );
         report(
            "settings layer",
            phoenix_sigs::macos::settings_layer(image).map(at),
         );
         report(
            "animation frame",
            phoenix_sigs::macos::animation_frame(image).map(at),
         );
         report(
            "scale fade",
            phoenix_sigs::macos::scale_fade(image).map(|sf| {
               format!(
                  "{} (loc {}) {:x?}",
                  at(sf.into_any),
                  at(sf.caller_loc),
                  sf.layout
               )
            }),
         );
         report(
            "native modal",
            gpui
               .as_ref()
               .map_err(|_| "needs gpui builders".to_owned())
               .and_then(|gpui| {
                  let layout = gpui_layout
                     .as_ref()
                     .map_err(|_| "needs gpui layouts".to_owned())?;
                  phoenix_sigs::macos::modal(image, gpui.div_into_any, &layout.div)
               })
               .map(|modal| {
                  format!(
                     "overlay {}, modal {}, {:x?}",
                     at(modal.overlay_render),
                     at(modal.modal_new),
                     modal.layout
                  )
               }),
         );
         report(
            "native text fields",
            phoenix_sigs::macos::text_fields(image).map(|fields| {
               format!(
                  "single {}, multi {}, {:x?}",
                  at(fields.cx_new_single),
                  at(fields.cx_new_multiline),
                  fields.layout
               )
            }),
         );
         report(
            "svg builders",
            phoenix_sigs::macos::svg_builders(image).map(|svg| format!("{svg:x?}")),
         );
         report(
            "asset loader",
            phoenix_sigs::macos::asset_load(image).map(at),
         );
         report(
            "mouse down",
            gpui_layout
               .as_ref()
               .map_err(|_| "needs gpui layouts".to_owned())
               .and_then(|layout| phoenix_sigs::macos::mouse_down(image, &layout.div))
               .map(|dismiss| format!("{dismiss:x?}")),
         );
         report(
            "message header",
            phoenix_sigs::macos::message_header(image).map(|header| format!("{header:x?}")),
         );
         report(
            "member row",
            phoenix_sigs::macos::member_row(image).map(|row| format!("{row:x?}")),
         );
         report(
            "dm row",
            phoenix_sigs::macos::dm_row(image).map(|row| format!("{row:x?}")),
         );
         report(
            "message json",
            phoenix_sigs::macos::message_writer(image).map(|found| format!("{found:x?}")),
         );
         report(
            "access enforced",
            phoenix_sigs::macos::access_read(image)
               .and_then(|read| phoenix_sigs::macos::access_enforced(image, read))
               .map(at),
         );
         report(
            "pages under frame",
            phoenix_sigs::macos::pages_under_frame(image).map(at),
         );
         report(
            "relaunch script",
            phoenix_sigs::macos::relaunch_script(image).map(at),
         );
      },
      Machine::Aarch64 if macho => {
         report(
            "guest bridge",
            ios::bridge(image).map(|bridge| {
               format!(
                  "{:#x}, vtable {:#x}, dispatch at +{:#x}, host vtable {:#x}",
                  bridge.call, bridge.vtable, bridge.dispatch, bridge.host_vtable
               )
            }),
         );
         let names = ["Networking.request", "@http", "headers"];
         report("host names", match ios::host_names(image, &names)[..] {
            [Some(request), Some(http), Some(headers)] => {
               Ok(format!(
                  "request {request}, @http {http}, headers {headers}"
               ))
            },
            ref numbers => Err(format!("{names:?} read as {numbers:?}")),
         });
         report(
            "access gate",
            locate::mobile::access_gate(ix)
               .map(|[first, second]| format!("{first:#x}, {second:#x}")),
         );
      },
      Machine::Aarch64 | Machine::Arm => {},
   }
   for locator in LOCATORS
      .iter()
      .filter(|locator| locator.families.contains(&family))
   {
      report(locator.name, (locator.run)(ix));
   }
   if missed > 0 {
      return Err(misstep::Report::msg(format!(
         "{missed} locators missed this build"
      )));
   }
   Ok(())
}

fn dump(image: &Image<'_>) -> misstep::Result<()> {
   match image.build_id {
      Some(id) => println!("{} build {id}", image.file_name()),
      None => println!("{} without a build ID", image.file_name()),
   }

   let registry = GatewayRegistry::locate(image)?;
   let mut sharing: HashMap<usize, Vec<&str>> = HashMap::new();
   for (_, entry) in registry.iter() {
      sharing.entry(entry.handler).or_default().push(&entry.name);
   }
   println!(
      "registry: {} events, {} handlers",
      registry.iter().count(),
      sharing.len()
   );

   for (_, entry) in registry.iter() {
      let shared = sharing[&entry.handler]
         .iter()
         .filter(|name| **name != entry.name)
         .collect::<Vec<&&str>>();

      let note = if shared.is_empty() {
         String::new()
      } else {
         format!(" shared with {shared:?}")
      };

      println!("   {:<40} {:#010x}{note}", entry.name, entry.handler);
   }
   let http = if image.function_starts.is_some() {
      phoenix_sigs::macos::http_transport(image)
   } else {
      DesktopHttpTransport::locate(image)
   };
   if let Ok(http) = http {
      let fmt_opt = |addr: Option<usize>| {
         addr.map_or_else(|| "none".to_owned(), |addr| format!("{addr:#010x}"))
      };
      println!(
         "http:     send={:#010x} ({} slots), poll={:#010x} ({} slots), alloc={}, dealloc={}",
         http.send_fn,
         http.send_slots.len(),
         http.poll_fn,
         http.poll_slots.len(),
         fmt_opt(http.host_alloc),
         fmt_opt(http.host_dealloc),
      );
   }
   Ok(())
}

struct Tools<'a> {
   image: &'a Image<'a>,
   base:  usize,
   /// Mach-O files are arm64, everything else sigscan reads as x86-64 here.
   arm64: bool,
}

impl Tools<'_> {
   /// The arm64 function holding `from`, with its outlined stubs inlined,
   /// from `from` to `to`: calls, immediates and the addresses `adrp`
   /// pairs load (with the bytes there when they read as text).
   fn flat(&self, from: usize, to: usize) {
      use phoenix_hook::arm64::Insn;
      let Some(func) = self.image.function_containing(from) else {
         println!("{} is in no function", self.at(from));
         return;
      };
      let mut pages = [None::<usize>; 32];
      for (pc, insn) in phoenix_sigs::macos::flattened_at(self.image, func) {
         if let Insn::Adrp { rd, page } = insn {
            pages[usize::from(rd)] = Some(page);
         }
         if !(from..to).contains(&pc) {
            continue;
         }
         let text = match insn {
            Insn::Bl { target } => format!("call {target:#x}"),
            Insn::AddImm { rd, rn, imm } => {
               match pages[usize::from(rn)] {
                  Some(page) if rn != 31 => {
                     let addr = page + imm;
                     let preview = self.image.read(addr, 24).map_or_else(String::new, |bytes| {
                        String::from_utf8_lossy(bytes).replace(|c: char| c.is_control(), ".")
                     });
                     format!("x{rd} = {addr:#x} \"{preview}\"")
                  },
                  _ => format!("{insn:x?}"),
               }
            },
            Insn::Adrp { .. } => continue,
            other => format!("{other:x?}"),
         };
         println!("{pc:#x}  {text}");
      }
   }

   fn at(&self, addr: usize) -> String {
      format!("{addr:#x} (rva {:#x})", addr - self.base)
   }

   fn strings(&self, text: &str) -> misstep::Result<()> {
      let found = self.image.find_bytes(text.as_bytes());
      if found.is_empty() {
         return Err(misstep::Report::msg(format!("{text:?} is not in the file")));
      }
      if self.arm64 {
         for at in found.into_iter().take(16) {
            println!("{text:?} at {}", self.at(at));
            // Rust packs string literals together, so a load may start earlier.
            self.print_arm64_refs(at.saturating_sub(0x40)..at + 1);
         }
         return Ok(());
      }
      for at in found.into_iter().take(16) {
         println!("{text:?} at {}", self.at(at));
         let loads = x86::literal_loads(self.image, at);
         match loads.first().and_then(|load| load.line.target) {
            None => println!("   no code loads it"),
            Some(start) if start != at => {
               println!("   literal starts {} bytes earlier", at - start);
            },
            Some(_) => {},
         }
         for load in loads.iter().take(32) {
            self.print_site(load);
         }
      }
      Ok(())
   }

   fn scan(&self, pattern: &str) -> misstep::Result<()> {
      let pattern = Pattern::leak(pattern.to_owned()).context(USAGE)?;
      let found = self.image.scan(pattern);
      println!("{} matches", found.len());
      for at in found.into_iter().take(64) {
         let function = self
            .image
            .function_bounds(at)
            .map(|(start, _)| format!("  in fn {} +{:#x}", self.at(start), at - start));
         println!("   {}{}", self.at(at), function.unwrap_or_default());
      }
      Ok(())
   }

   fn print_arm64_refs(&self, targets: std::ops::Range<usize>) {
      let refs = arm64::code_refs(self.image, std::slice::from_ref(&targets));
      if refs.is_empty() {
         println!("   no code loads it");
      }
      for (site, target) in refs.into_iter().take(64) {
         let function = self
            .image
            .function_bounds(site)
            .map(|(start, _)| format!("   in fn {} +{:#x}", self.at(start), site - start));
         println!(
            "   {} -> {}{}",
            self.at(site),
            self.at(target),
            function.unwrap_or_default()
         );
      }
   }

   fn refs(&self, target: usize) {
      if self.arm64 {
         self.print_arm64_refs(target..target + 1);
         for pointer in self.image.pointers_to(target).into_iter().take(64) {
            println!("   pointer at {}", self.at(pointer));
         }
         return;
      }
      let code = x86::code_refs(self.image, target..target + 1);
      let pointers = self.image.pointers_to(target);
      println!(
         "{}: {} code refs, {} pointers",
         self.at(target),
         code.len(),
         pointers.len()
      );
      for site in code.iter().take(64) {
         self.print_site(site);
      }
      for pointer in pointers.into_iter().take(64) {
         println!("   pointer at {}", self.at(pointer));
      }
   }

   fn print_site(&self, site: &x86::CodeRef) {
      println!(
         "   {}  {}   in fn {} +{:#x}",
         self.at(site.line.addr),
         site.line.text,
         self.at(site.function),
         site.line.addr - site.function
      );
   }

   fn dis(&self, addr: usize, count: usize) {
      let mapped = self
         .image
         .segments
         .iter()
         .find(|segment| segment.contains(addr))
         .map_or(0, |segment| segment.addr + segment.bytes.len() - addr);
      let Some(code) = self
         .image
         .read(addr, mapped.min(16 * count))
         .filter(|code| !code.is_empty())
      else {
         println!("{} is not mapped", self.at(addr));
         return;
      };
      let end = match self.image.function_bounds(addr) {
         Some((start, end)) => {
            println!("fn {} .. {:#x}, {} bytes", self.at(start), end, end - start);
            end
         },
         None => usize::MAX,
      };
      if self.arm64 {
         for (at, text) in arm64::disasm(code, addr, count) {
            if at >= end {
               println!("   -- end of function --");
               break;
            }
            println!("   {}  {text}", self.at(at));
         }
         return;
      }
      for line in x86::disasm(code, addr, count) {
         if line.addr >= end {
            println!("   -- end of function --");
            break;
         }
         // Calls and jumps through a pointer slot, as ELF builds make them,
         // print where the slot points.
         let bytes = &code[line.addr - addr..];
         let through = match bytes {
            [0xFF, 0x15, ..] => x86::call_target(self.image, bytes, line.addr).map(|(_, to)| to),
            [0xFF, 0x25, ..] => x86::jump_target(self.image, bytes, line.addr),
            _ => None,
         };
         match through {
            Some(to) => println!("   {}  {}   -> {to:#x}", self.at(line.addr), line.text),
            None => println!("   {}  {}", self.at(line.addr), line.text),
         }
      }
   }
}
