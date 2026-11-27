//! `.theme.css` parsing and the HSLA remaps applied to GPUI's quads, borders
//! and monochrome sprites.
#![cfg_attr(
   not(windows),
   expect(dead_code, reason = "only Windows observes the renderer")
)]

use std::collections::HashMap;

/// GPUI's color, every channel in `0.0..=1.0`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Hsla {
   pub h: f32,
   pub s: f32,
   pub l: f32,
   pub a: f32,
}

/// The four background levels, from the server rail up to popovers.
#[derive(Clone, Copy, Debug)]
pub struct Palette {
   pub tertiary:  Hsla,
   pub secondary: Hsla,
   pub primary:   Hsla,
   pub elevated:  Hsla,
}

#[derive(Clone, Debug)]
pub struct Theme {
   pub active:         bool,
   pub name:           String,
   pub bg:             Option<Palette>,
   pub accent:         Option<Hsla>,
   pub ui_border:      Option<Hsla>,
   pub text_normal:    Option<Hsla>,
   pub text_muted:     Option<Hsla>,
   pub radius_scale:   Option<f32>,
   pub override_nitro: bool,
}

impl Default for Theme {
   fn default() -> Self {
      Self {
         active:         false,
         name:           String::new(),
         bg:             None,
         accent:         None,
         ui_border:      None,
         text_normal:    None,
         text_muted:     None,
         radius_scale:   None,
         override_nitro: true,
      }
   }
}

/// Where a quad sits in the window, guessed from its bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuadRole {
   Default,
   FullWindowRoot,
   ServerRail,
   Sidebar,
   MainPane,
   HeaderBar,
}

/// Clamps to `0.0..=1.0`, with `NaN` read as `0.0`.
#[must_use]
pub const fn clamp01(v: f32) -> f32 {
   if v.is_nan() { 0.0 } else { v.clamp(0.0, 1.0) }
}

#[must_use]
#[expect(clippy::many_single_char_names, reason = "the color channels")]
pub fn rgb_to_hsla(r: f32, g: f32, b: f32, a: f32) -> Hsla {
   let (r, g, b, a) = (clamp01(r), clamp01(g), clamp01(b), clamp01(a));
   let (max, min) = (r.max(g).max(b), r.min(g).min(b));
   let delta = max - min;
   let l = f32::midpoint(max, min);
   if delta <= 1.0e-6 {
      return Hsla {
         h: 0.0,
         s: 0.0,
         l,
         a,
      };
   }
   let s = if l > 0.5 {
      delta / (2.0 - max - min)
   } else {
      delta / (max + min)
   };
   let h = if (max - r).abs() <= f32::EPSILON {
      (g - b) / delta + if g < b { 6.0 } else { 0.0 }
   } else if (max - g).abs() <= f32::EPSILON {
      (b - r) / delta + 2.0
   } else {
      (r - g) / delta + 4.0
   };
   Hsla {
      h: (h / 6.0).rem_euclid(1.0),
      s,
      l,
      a,
   }
}

fn lerp_hsla(a: Hsla, b: Hsla, t: f32) -> Hsla {
   let t = clamp01(t);
   let lerp = |x: f32, y: f32| (y - x).mul_add(t, x);
   // A grey has no meaningful hue, so it takes the other stop's.
   let h = if a.s < 0.02 {
      b.h
   } else if b.s < 0.02 {
      a.h
   } else {
      let diff = (b.h - a.h + 0.5).rem_euclid(1.0) - 0.5;
      diff.mul_add(t, a.h).rem_euclid(1.0)
   };
   Hsla {
      h,
      s: lerp(a.s, b.s),
      l: lerp(a.l, b.l),
      a: lerp(a.a, b.a),
   }
}

/// A leading number and what follows it, such as a unit.
fn number(s: &str) -> Option<(f32, &str)> {
   let end = s
      .char_indices()
      .find(|&(i, c)| !(c.is_ascii_digit() || c == '.' || (i == 0 && matches!(c, '+' | '-'))))
      .map_or(s.len(), |(i, _)| i);
   let v: f32 = s[..end].parse().ok()?;
   v.is_finite().then_some((v, &s[end..]))
}

/// `rgb()`/`hsl()` arguments with their units, comma or space separated.
fn color_args(text: &str) -> Option<Vec<(f32, &str)>> {
   let inner = &text[text.find('(')? + 1..text.rfind(')')?];
   let args = inner
      .split([' ', ',', '/', '\t'])
      .filter(|t| !t.is_empty())
      .map(number)
      .collect::<Option<Vec<_>>>()?;
   (3..=4).contains(&args.len()).then_some(args)
}

fn alpha(args: &[(f32, &str)]) -> f32 {
   args
      .get(3)
      .map_or(1.0, |&(v, unit)| if unit == "%" { v / 100.0 } else { v })
}

/// Parses `#rgb`, `#rrggbb`, `#rrggbbaa`, `rgb[a]()` and `hsl[a]()`.
#[must_use]
pub fn parse_css_color(raw: &str) -> Option<Hsla> {
   let lower = raw.trim().to_ascii_lowercase();
   if let Some(hex) = lower.strip_prefix('#') {
      let hex = match hex.len() {
         3 => {
            hex.chars()
               .flat_map(|c| [c, c])
               .chain("ff".chars())
               .collect()
         },
         6 => format!("{hex}ff"),
         8 => hex.to_owned(),
         _ => return None,
      };
      let [r, g, b, a] = u32::from_str_radix(&hex, 16)
         .ok()?
         .to_be_bytes()
         .map(f32::from);
      return Some(rgb_to_hsla(r / 255.0, g / 255.0, b / 255.0, a / 255.0));
   }
   if lower.starts_with("rgb") {
      let args = color_args(&lower)?;
      let ch = |i: usize| {
         let (v, unit) = args[i];
         if unit == "%" { v / 100.0 } else { v / 255.0 }
      };
      return Some(rgb_to_hsla(ch(0), ch(1), ch(2), alpha(&args)));
   }
   if lower.starts_with("hsl") {
      let args = color_args(&lower)?;
      let (hue, unit) = args[0];
      let turns = match unit {
         "turn" => hue,
         "grad" => hue / 400.0,
         "rad" => hue / std::f32::consts::TAU,
         _ => hue / 360.0,
      };
      return Some(Hsla {
         h: turns.rem_euclid(1.0),
         s: clamp01(args[1].0 / 100.0),
         l: clamp01(args[2].0 / 100.0),
         a: clamp01(alpha(&args)),
      });
   }
   None
}

/// The stylesheet without comments, and the `@name` from its header.
fn strip_comments(css: &str) -> (String, String) {
   let mut clean = String::with_capacity(css.len());
   let mut name = String::new();
   let mut rest = css;
   while let Some(start) = rest.find("/*") {
      clean.push_str(&rest[..start]);
      let Some(len) = rest[start + 2..].find("*/") else {
         return (clean, name);
      };
      let comment = &rest[start + 2..start + 2 + len];
      if name.is_empty()
         && let Some(at) = comment.find("@name")
      {
         comment[at + 5..]
            .lines()
            .next()
            .unwrap_or_default()
            .trim()
            .clone_into(&mut name);
      }
      rest = &rest[start + 2 + len + 2..];
   }
   clean.push_str(rest);
   (clean, name)
}

/// Every `--custom-property: value` declaration, keyed in lowercase.
fn css_vars(clean: &str) -> HashMap<String, String> {
   let mut vars = HashMap::new();
   let mut pos = 0;
   while let Some(rel) = clean[pos..].find("--") {
      let dash = pos + rel;
      pos = dash + 2;
      // Only a declaration, never `var(--x)` or `url("a--b.png")`.
      if dash > 0
         && !matches!(
            clean.as_bytes()[dash - 1],
            b' ' | b'\t' | b'\r' | b'\n' | b';' | b'{'
         )
      {
         continue;
      }
      let Some(colon) = clean[pos..].find(':').map(|c| pos + c) else {
         break;
      };
      if clean[pos..colon].contains([';', '{', '}', '(', ')', '"', '\'']) {
         continue;
      }
      let end = clean[colon + 1..]
         .find([';', '}'])
         .map_or(clean.len(), |e| colon + 1 + e);
      let value = clean[colon + 1..end].trim();
      let value = value
         .to_ascii_lowercase()
         .find("!important")
         .map_or(value, |i| value[..i].trim());
      if !value.is_empty() {
         vars.insert(
            clean[dash..colon].trim().to_ascii_lowercase(),
            value.to_owned(),
         );
      }
      pos = end;
   }
   vars
}

#[must_use]
pub fn parse_theme_css(css: &str) -> Theme {
   let (clean, name) = strip_comments(css);
   let vars = css_vars(&clean);
   let color = |keys: &[&str]| keys.iter().find_map(|k| parse_css_color(vars.get(*k)?));
   let float = |keys: &[&str], range: std::ops::RangeInclusive<f32>| {
      keys.iter().find_map(|k| {
         let (v, unit) = number(vars.get(*k)?.trim())?;
         let v = if unit.starts_with('%') { v / 100.0 } else { v };
         range.contains(&v).then_some(v)
      })
   };

   let tertiary = color(&[
      "--bg-tertiary",
      "--background-tertiary",
      "--bg-base-tertiary",
      "--bg-1",
   ]);
   let secondary = color(&[
      "--bg-secondary",
      "--background-secondary",
      "--bg-base-secondary",
      "--bg-2",
   ]);
   let primary = color(&[
      "--bg-primary",
      "--background-primary",
      "--bg-base-primary",
      "--bg-3",
   ]);
   let elevated = color(&[
      "--bg-elevated",
      "--background-floating",
      "--background-modifier-hover",
      "--bg-4",
   ]);
   // A theme may set any one level; the rest are derived from it.
   let bg = primary.or(secondary).or(tertiary).or(elevated).map(|base| {
      let primary = primary.unwrap_or(base);
      let secondary = secondary.unwrap_or_else(|| {
         Hsla {
            l: clamp01(primary.l * 0.80),
            ..primary
         }
      });
      Palette {
         tertiary: tertiary.unwrap_or_else(|| {
            Hsla {
               l: clamp01(secondary.l * 0.72),
               ..secondary
            }
         }),
         secondary,
         primary,
         elevated: elevated.unwrap_or_else(|| {
            Hsla {
               l: clamp01(primary.l + 0.08),
               ..primary
            }
         }),
      }
   });

   let defaults = Theme::default();
   let mut t = Theme {
      name,
      bg,
      accent: color(&[
         "--accent-color",
         "--brand-experiment",
         "--brand-500",
         "--accent-1",
         "--accent-2",
      ]),
      ui_border: color(&[
         "--ui-border-color",
         "--background-modifier-accent",
         "--border-subtle",
      ]),
      text_normal: color(&["--text-normal", "--text-primary", "--text-1", "--text-2"]),
      text_muted: color(&["--text-muted", "--text-secondary", "--text-3", "--text-4"]),
      radius_scale: float(&["--radius-scale"], 0.0..=2.5),
      override_nitro: vars.get("--override-nitro").is_none_or(|v| {
         !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "false" | "0" | "off"
         )
      }),
      ..defaults
   };
   t.active = t.bg.is_some()
      || t.accent.is_some()
      || t.ui_border.is_some()
      || t.text_normal.is_some()
      || t.text_muted.is_some()
      || t.radius_scale.is_some();
   t
}

fn is_blurple(c: Hsla) -> bool {
   c.a > 0.01 && c.s >= 0.42 && (0.59..=0.71).contains(&c.h) && (0.38..=0.82).contains(&c.l)
}

/// Moves `c` onto `to`, keeping how far its lightness sat from `pivot`.
fn tint(c: &mut Hsla, to: Hsla, pivot: f32, keep: f32) {
   let l = clamp01((c.l - pivot).mul_add(keep, to.l));
   *c = Hsla { l, a: c.a, ..to };
}

/// Recolors a quad fill or gradient stop.
pub fn remap_quad_color(
   t: &Theme,
   c: &mut Hsla,
   is_large_panel: bool,
   force_background: bool,
   is_full_window_root: bool,
   mut role: QuadRole,
) {
   if !t.active || c.a <= 0.005 {
      return;
   }
   if is_full_window_root && role == QuadRole::Default {
      role = QuadRole::FullWindowRoot;
   }
   let is_structural = role != QuadRole::Default;
   // Structural chrome keeps its color so a Nitro gradient never turns into the
   // accent.
   if !force_background
      && !is_structural
      && let Some(accent) = t.accent
      && is_blurple(*c)
   {
      tint(c, accent, 0.65, 0.75);
      return;
   }

   let is_surface = force_background
      || is_structural
      || (c.s <= 0.24 && c.l <= 0.42)
      || c.l <= 0.22
      || (is_large_panel && c.l <= 0.50);
   if let Some(bg) = t.bg
      && is_surface
   {
      let mapped = match role {
         QuadRole::ServerRail | QuadRole::HeaderBar => bg.tertiary,
         QuadRole::Sidebar => bg.secondary,
         QuadRole::FullWindowRoot | QuadRole::MainPane => bg.primary,
         // Discord's dark levels, measured on the default dark theme.
         QuadRole::Default => {
            const L: [f32; 4] = [0.055, 0.105, 0.165, 0.265];
            let l = if force_background { c.l.min(L[2]) } else { c.l };
            if l <= L[0] {
               Hsla {
                  l: clamp01(bg.tertiary.l * 0.18_f32.mul_add(l / L[0], 0.82)),
                  ..bg.tertiary
               }
            } else if l <= L[1] {
               lerp_hsla(bg.tertiary, bg.secondary, (l - L[0]) / (L[1] - L[0]))
            } else if l <= L[2] {
               lerp_hsla(bg.secondary, bg.primary, (l - L[1]) / (L[2] - L[1]))
            } else if l <= L[3] {
               lerp_hsla(bg.primary, bg.elevated, (l - L[2]) / (L[3] - L[2]))
            } else {
               Hsla {
                  l: clamp01((l - L[3]).mul_add(0.45, bg.elevated.l)),
                  ..bg.elevated
               }
            }
         },
      };
      *c = Hsla { a: c.a, ..mapped };
   }

   // A Nitro client theme draws the chrome translucent over its gradient;
   // opaque, the theme's own colors show instead.
   if t.bg.is_some()
      && is_surface
      && t.override_nitro
      && (is_large_panel || is_structural)
      && c.a >= 0.45
   {
      c.a = 1.0;
   }
}

/// Recolors both stops of a linear gradient together.
///
/// GPUI interpolates linear gradients in non-premultiplied sRGB/Oklab, so a
/// stop with `a == 0.0` still contributes its hue across the gradient when the
/// other stop is visible. Both stops are remapped whenever either is visible,
/// while keeping a transparent stop transparent.
pub fn remap_gradient_stops(
   t: &Theme,
   stops: &mut [Hsla; 2],
   is_large_panel: bool,
   is_huge_panel: bool,
   is_full_window_root: bool,
   role: QuadRole,
) {
   let max_a = stops[0].a.max(stops[1].a);
   let min_a = stops[0].a.min(stops[1].a);
   if !t.active || max_a <= 0.005 || max_a > 1.001 {
      return;
   }
   // Nitro client themes layer 2-stop gradients fading from alpha 0 to 1 on
   // every themed surface, including narrow inputs and the message editor.
   let nitro_fade = t.override_nitro && min_a <= 0.005 && max_a >= 0.45;
   let force_background = is_huge_panel || role != QuadRole::Default || nitro_fade;
   for stop in stops {
      let orig_a = stop.a;
      if orig_a.is_nan() || !(0.0..=1.001).contains(&orig_a) {
         continue;
      }
      if orig_a <= 0.005 {
         stop.a = max_a;
      }
      remap_quad_color(
         t,
         stop,
         is_large_panel,
         force_background,
         is_full_window_root,
         role,
      );
      if orig_a <= 0.005 {
         stop.a = orig_a;
      }
   }
}

pub fn remap_border_color(t: &Theme, c: &mut Hsla) {
   if !t.active || c.a <= 0.005 {
      return;
   }
   let to = if is_blurple(*c) {
      t.accent
   } else {
      t.ui_border.filter(|_| c.s <= 0.24)
   };
   if let Some(to) = to {
      *c = Hsla { a: c.a, ..to };
   }
}

/// Recolors a text glyph or monochrome icon.
pub fn remap_mono_color(t: &Theme, c: &mut Hsla) {
   if !t.active || c.a <= 0.005 {
      return;
   }
   if let Some(accent) = t.accent
      && is_blurple(*c)
   {
      tint(c, accent, 0.65, 0.75);
   } else if c.s <= 0.24 {
      if let Some(normal) = t.text_normal
         && c.l >= 0.72
      {
         tint(c, normal, 0.88, 0.60);
      } else if let Some(muted) = t.text_muted
         && (0.38..0.72).contains(&c.l)
      {
         tint(c, muted, 0.56, 0.65);
      }
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn parses_aliases_units_and_ignores_var_refs() {
      let th = parse_theme_css(
         r"
         /* @name UnitTest Theme */
         :root {
            --background-tertiary: #11111b;
            --background-primary: rgb(30, 30, 46);
            --bg-elevated: hsl(237deg, 16%, 23%);
            background: var(--background-primary);
            --brand-experiment: #ff79c6 !important;
            --ui-border-color: rgba(122, 162, 247, 50%);
            --text-normal: #fce8f3;
            --radius-scale: 125%;
            --override-nitro: off;
         }
      ",
      );
      assert!(th.active);
      assert_eq!(th.name, "UnitTest Theme");
      assert!(th.bg.is_some() && th.accent.is_some());
      assert!((th.ui_border.unwrap().a - 0.50).abs() < 0.02);
      assert_eq!(th.radius_scale, Some(1.25));
      assert!(!th.override_nitro);
      let blue = parse_css_color("#00f").unwrap();
      assert!((blue.h - 2.0 / 3.0).abs() < 0.01);
   }

   #[test]
   fn keeps_green_and_remaps_blurple_and_roles() {
      let th = parse_theme_css(
         ":root { --bg-tertiary: #11111b; --bg-secondary: #181825; --bg-primary: #1e1e2e; \
          --accent-color: #ff79c6; --ui-border-color: #313244; --text-normal: #cdd6f4; }",
      );
      let bg = th.bg.unwrap();
      let mut blurple = parse_css_color("#5865f2").unwrap();
      remap_quad_color(&th, &mut blurple, false, false, false, QuadRole::Default);
      assert!((blurple.h - th.accent.unwrap().h).abs() < 0.02);

      let mut green = parse_css_color("#23a55a").unwrap();
      let hue = green.h;
      remap_quad_color(&th, &mut green, false, false, false, QuadRole::Default);
      assert!((green.h - hue).abs() < 0.001);

      let mut rail = Hsla {
         h: 0.72,
         s: 0.50,
         l: 0.14,
         a: 1.0,
      };
      remap_quad_color(&th, &mut rail, true, false, false, QuadRole::ServerRail);
      assert!((rail.l - bg.tertiary.l).abs() < 0.01);

      let mut border = Hsla {
         h: 0.0,
         s: 0.05,
         l: 0.25,
         a: 1.0,
      };
      remap_border_color(&th, &mut border);
      assert!((border.h - th.ui_border.unwrap().h).abs() < 0.02);

      let mut text = Hsla {
         h: 0.0,
         s: 0.05,
         l: 0.90,
         a: 1.0,
      };
      remap_mono_color(&th, &mut text);
      assert!((text.h - th.text_normal.unwrap().h).abs() < 0.02);
   }

   #[test]
   fn remaps_transparent_nitro_gradient_stop_and_keeps_nameplates() {
      let th = parse_theme_css(
         ":root { --bg-tertiary: #11111b; --bg-secondary: #181825; --bg-primary: #1e1e2e; \
          --bg-elevated: #313244; --accent-color: #cba6f7; }",
      );
      let bg = th.bg.unwrap();

      // Nitro sunset gradient layer (alpha 0 -> 1) on a narrow input/editor
      // quad.
      let mut nitro = [
         Hsla {
            h: 0.7865,
            s: 0.99,
            l: 0.23,
            a: 0.0,
         },
         Hsla {
            h: 0.7865,
            s: 0.99,
            l: 0.23,
            a: 1.0,
         },
      ];
      remap_gradient_stops(&th, &mut nitro, false, false, false, QuadRole::Default);
      assert!((nitro[0].h - bg.primary.h).abs() < 0.02);
      assert!((nitro[1].h - bg.primary.h).abs() < 0.02);
      assert!(nitro[0].a.abs() < f32::EPSILON);
      assert!((nitro[1].a - 1.0).abs() < f32::EPSILON);

      // Low-alpha member nameplate gradient stays untouched.
      let mut nameplate = [
         Hsla {
            h: 0.14,
            s: 0.93,
            l: 0.52,
            a: 0.0,
         },
         Hsla {
            h: 0.14,
            s: 0.93,
            l: 0.52,
            a: 0.20,
         },
      ];
      remap_gradient_stops(&th, &mut nameplate, false, false, false, QuadRole::Default);
      assert!((nameplate[0].h - 0.14).abs() < 0.001);
      assert!((nameplate[1].h - 0.14).abs() < 0.001);
      assert!(nameplate[0].a.abs() < f32::EPSILON);
      assert!((nameplate[1].a - 0.20).abs() < 0.001);

      // Dark blue-violet Nitro base quad must remap to background, not accent.
      let mut base = Hsla {
         h: 0.668,
         s: 0.574,
         l: 0.305,
         a: 1.0,
      };
      remap_quad_color(&th, &mut base, true, false, false, QuadRole::Default);
      assert!((base.h - bg.elevated.h).abs() < 0.02);
      assert!((base.s - bg.elevated.s).abs() < 0.05);
   }
}
