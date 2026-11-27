//! What a plugin's banner lets it reach. A plugin's `phoenix` object leaves out
//! what it did not declare, and the calls that take a route, host or event
//! refuse the ones outside its lines.
//!
//! - `// @gateway messageCreate messageUpdate` for gateway hook points.
//! - `// @gateway-send 4` for outgoing gateway opcodes.
//! - `// @discord GET /channels/*/messages` for `phoenix.discord` requests and
//!   interceptors, one route a line. `*` is one path segment, a final `**` the
//!   rest, and `*` in place of the method any method.
//! - `// @fetch translate.googleapis.com *.example.com` for `phoenix.fetch`.
//! - `// @stores`, `// @messages` and `// @bridge` for those namespaces whole.
//! - `// @ui-tree` for the raw view tree, which holds whatever the screen
//!   shows.
//!
//! Images Discord draws reach the network too. An icon a plugin draws, and a
//! URL host a hook adds to what Discord renders, must be one of its `@fetch`
//! hosts or Discord's own.

use std::{
   collections::{
      BTreeMap,
      BTreeSet,
   },
   fmt,
   str::FromStr,
};

use serde::{
   Deserializer,
   de::{
      DeserializeSeed,
      MapAccess,
      SeqAccess,
      Visitor,
   },
};

use crate::banner;

#[derive(Debug, flub::Error)]
pub enum PermissionError {
   #[error("@gateway-send {0}: opcodes are integers")]
   Opcode(String),
   #[error("@discord {0}: write a method and a path starting with /, like GET /users/@me")]
   Route(String),
   #[error("@discord {0}: ** only ends a route")]
   Rest(String),
   #[error("@fetch: {0} is not a host name")]
   Host(String),
}

pub enum Permissions {
   /// The debug shell's prompt, which reaches everything.
   Console,
   Declared(Declared),
}

#[derive(Default)]
pub struct Declared {
   gateway:      BTreeSet<String>,
   gateway_send: BTreeSet<u32>,
   discord:      Vec<Route>,
   fetch:        Vec<Host>,
   whole:        BTreeSet<Namespace>,
}

/// The namespaces a plugin reaches whole or not at all.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Namespace {
   Stores,
   Messages,
   Bridge,
   UiTree,
}

impl Namespace {
   const fn key(self) -> &'static str {
      match self {
         Self::Stores => "stores",
         Self::Messages => "messages",
         Self::Bridge => "bridge",
         Self::UiTree => "ui-tree",
      }
   }
}

/// Hosts any plugin may point Discord at, since they reach only Discord.
fn discord_host(host: &str) -> bool {
   [
      "discord.com",
      "discordapp.com",
      "discord.gg",
      "discordapp.net",
   ]
   .iter()
   .any(|domain| {
      host == *domain
         || host
            .strip_suffix(domain)
            .is_some_and(|sub| sub.ends_with('.'))
   })
}

/// The mobile sink draws `…/badge-icons/phx_u_<hex>.png` from the URL the hex
/// spells, so a badge path counts as that URL.
const BADGE: &str = "phx_u_";

/// The `https://` URL `hex` spells.
#[must_use]
pub fn badge_target(hex: &str) -> Option<String> {
   if hex.is_empty() || !hex.len().is_multiple_of(2) {
      return None;
   }
   let bytes = hex
      .as_bytes()
      .as_chunks::<2>()
      .0
      .iter()
      .map(|&[high, low]| {
         let high = char::from(high).to_digit(16)?;
         let low = char::from(low).to_digit(16)?;
         u8::try_from((high << 4) | low).ok()
      })
      .collect::<Option<Vec<u8>>>()?;
   String::from_utf8(bytes)
      .ok()
      .filter(|url| url.starts_with("https://"))
}

/// A host a client could connect to for a URL.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum UrlHost {
   Named(String),
   /// Brackets, percent escapes or other bytes a host name lacks, which a
   /// client may decode into any host.
   Unreadable,
}

impl fmt::Display for UrlHost {
   fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
      match self {
         Self::Named(name) => formatter.write_str(name),
         Self::Unreadable => formatter.write_str("a host with escaped or bracketed bytes"),
      }
   }
}

/// The hosts after `http:` or `https:`. `OkHttp` ends the authority at `\` and
/// takes the last `@`, `java.net.URL` reads past `\` and takes the first,
/// WHATWG drops tabs and newlines, and the message linkifier stops at
/// whitespace, so each reading counts.
fn readings(rest: &str) -> BTreeSet<UrlHost> {
   let rest = rest.trim_start_matches(['/', '\\', '\t', '\n', '\r']);
   let wide = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
   let narrow = &wide[..wide.find('\\').unwrap_or(wide.len())];
   let word = &narrow[..narrow.find(char::is_whitespace).unwrap_or(narrow.len())];
   let joined = narrow.replace(['\t', '\n', '\r'], "");
   let mut found = BTreeSet::new();
   for authority in [wide, narrow, word, joined.as_str()] {
      let first = authority
         .split_once('@')
         .map_or(authority, |(_, host)| host);
      let last = authority
         .rsplit_once('@')
         .map_or(authority, |(_, host)| host);
      for userless in [first, last] {
         let host = userless.split(':').next().unwrap_or_default();
         if host.is_empty() || host.contains(char::is_whitespace) {
            continue;
         }
         let named = host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-');
         found.insert(if named {
            UrlHost::Named(host.to_ascii_lowercase())
         } else {
            UrlHost::Unreadable
         });
      }
   }
   found
}

/// The hosts `url` reaches when it is an `http(s)` URL.
#[must_use]
pub fn url_hosts(url: &str) -> Option<BTreeSet<UrlHost>> {
   let (scheme, rest) = url.split_once(':')?;
   if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")) {
      return None;
   }
   Some(readings(rest)).filter(|found| !found.is_empty())
}

/// The first host name `url` reaches, for messages.
#[must_use]
pub fn url_host(url: &str) -> Option<String> {
   url_hosts(url)?.into_iter().find_map(|host| {
      match host {
         UrlHost::Named(name) => Some(name),
         UrlHost::Unreadable => None,
      }
   })
}

/// Whether `url` is `original` with query pairs dropped, as tracker stripping
/// leaves it. Which pairs go is still a choice an attacker's link offers.
fn trimmed(original: &str, url: &str) -> bool {
   fn split(text: &str) -> (&str, &str, Option<&str>) {
      let (rest, fragment) = text
         .split_once('#')
         .map_or((text, None), |(rest, fragment)| (rest, Some(fragment)));
      let (base, query) = rest.split_once('?').unwrap_or((rest, ""));
      (base, query, fragment)
   }

   let (base, query, fragment) = split(original);
   let (trimmed_base, trimmed_query, trimmed_fragment) = split(url);
   if base != trimmed_base || fragment != trimmed_fragment {
      return false;
   }
   let mut pairs = query.split('&');
   trimmed_query
      .split('&')
      .filter(|pair| !pair.is_empty())
      .all(|kept| pairs.any(|pair| pair == kept))
}

/// The `http(s)` URLs in a text, keyed by how the text spells them up to the
/// next whitespace, with the hosts each reaches. JSON is read string by
/// string, so escapes cannot hide a URL.
#[derive(Default)]
pub struct Links(BTreeMap<String, BTreeSet<UrlHost>>);

impl Links {
   #[must_use]
   pub fn scan(text: &str) -> Self {
      let mut links = Self::default();
      let mut json = serde_json::Deserializer::from_str(text);
      let walked = Strings(&mut links)
         .deserialize(&mut json)
         .and_then(|()| json.end());
      if walked.is_err() {
         links = Self::default();
         links.plain(text);
      }
      links
   }

   fn plain(&mut self, text: &str) {
      let bytes = text.as_bytes();
      for (colon, _) in text.match_indices(':') {
         let scheme = |name: &str| {
            colon
               .checked_sub(name.len())
               .filter(|&start| bytes[start..colon].eq_ignore_ascii_case(name.as_bytes()))
         };
         let Some(start) = scheme("https").or_else(|| scheme("http")) else {
            continue;
         };
         let found = readings(&text[colon + 1..]);
         if found.is_empty() {
            continue;
         }
         let end = text[start..]
            .find(char::is_whitespace)
            .map_or(text.len(), |length| start + length);
         let url = text[start..end].trim_end_matches([
            '.', ',', '!', '?', ';', ':', ']', ')', '>', '"', '\'', '*', '~',
         ]);
         self.0.entry(url.to_owned()).or_default().extend(found);
      }
      for (at, _) in text.match_indices(BADGE) {
         let hex = text[at + BADGE.len()..]
            .split(|byte: char| !byte.is_ascii_hexdigit())
            .next()
            .unwrap_or_default();
         if let Some(target) = badge_target(hex) {
            self.plain(&target);
         }
      }
   }

   pub fn urls(&self) -> impl Iterator<Item = &str> {
      self.0.keys().map(String::as_str)
   }
}

/// Feeds every string in a JSON document, keys included, to [`Links::plain`].
struct Strings<'links>(&'links mut Links);

impl<'de> DeserializeSeed<'de> for Strings<'_> {
   type Value = ();

   fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
      deserializer.deserialize_any(self)
   }
}

impl<'de> Visitor<'de> for Strings<'_> {
   type Value = ();

   fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
      formatter.write_str("JSON")
   }

   fn visit_str<E>(self, text: &str) -> Result<(), E> {
      self.0.plain(text);
      Ok(())
   }

   fn visit_bool<E>(self, _: bool) -> Result<(), E> {
      Ok(())
   }

   fn visit_i64<E>(self, _: i64) -> Result<(), E> {
      Ok(())
   }

   fn visit_u64<E>(self, _: u64) -> Result<(), E> {
      Ok(())
   }

   fn visit_f64<E>(self, _: f64) -> Result<(), E> {
      Ok(())
   }

   fn visit_unit<E>(self) -> Result<(), E> {
      Ok(())
   }

   fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
      while seq.next_element_seed(Strings(&mut *self.0))?.is_some() {}
      Ok(())
   }

   fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
      while map.next_key_seed(Strings(&mut *self.0))?.is_some() {
         map.next_value_seed(Strings(&mut *self.0))?;
      }
      Ok(())
   }
}

struct Route {
   method:   Option<String>,
   segments: Vec<Segment>,
}

/// One thing a plugin reaches, as its settings page lists it.
#[derive(Clone, Debug)]
pub enum Grant {
   Events(Vec<String>),
   GatewaySend(Vec<u32>),
   Discord(String),
   Fetch(Vec<String>),
   Stores,
   Messages,
   Bridge,
   UiTree,
}

impl Grant {
   #[must_use]
   pub const fn label(&self) -> &'static str {
      match self {
         Self::Events(_) => "Gateway events",
         Self::GatewaySend(_) => "Gateway sends",
         Self::Discord(_) => "Discord API",
         Self::Fetch(_) => "Web hosts",
         Self::Stores => "Message cache",
         Self::Messages => "Outgoing messages",
         Self::Bridge => "Host modules",
         Self::UiTree => "Screen contents",
      }
   }
}

impl fmt::Display for Grant {
   fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
      match self {
         Self::Events(names) | Self::Fetch(names) => formatter.write_str(&names.join(", ")),
         Self::GatewaySend(ops) => {
            let ops = ops.iter().map(u32::to_string).collect::<Vec<_>>();
            write!(formatter, "opcode {}", ops.join(", "))
         },
         Self::Discord(route) => formatter.write_str(route),
         Self::Stores => formatter.write_str("read"),
         Self::Messages => formatter.write_str("read and rewrite"),
         Self::Bridge => formatter.write_str("full access"),
         Self::UiTree => formatter.write_str("read and change"),
      }
   }
}

impl fmt::Display for Route {
   fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
      formatter.write_str(self.method.as_deref().unwrap_or("*"))?;
      formatter.write_str(" ")?;
      for segment in &self.segments {
         formatter.write_str("/")?;
         match segment {
            Segment::Literal(literal) => formatter.write_str(literal)?,
            Segment::Any => formatter.write_str("*")?,
            Segment::Rest => formatter.write_str("**")?,
         }
      }
      Ok(())
   }
}

impl fmt::Display for Host {
   fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
      match self {
         Self::Exact(name) => formatter.write_str(name),
         Self::Under(name) => write!(formatter, "*.{name}"),
      }
   }
}

enum Segment {
   Literal(String),
   Any,
   Rest,
}

enum Host {
   Exact(String),
   /// `*.example.com`, which matches `cdn.example.com` and not `example.com`.
   Under(String),
}

impl FromStr for Permissions {
   type Err = PermissionError;

   fn from_str(source: &str) -> Result<Self, Self::Err> {
      let mut declared = Declared::default();
      for (key, value) in banner(source) {
         match key {
            "gateway" => {
               declared
                  .gateway
                  .extend(value.split_whitespace().map(str::to_owned));
            },
            "gateway-send" => {
               for op in value.split_whitespace() {
                  let op = op
                     .parse()
                     .map_err(|_| PermissionError::Opcode(op.to_owned()))?;
                  declared.gateway_send.insert(op);
               }
            },
            "discord" => declared.discord.push(value.parse()?),
            "fetch" => {
               for host in value.split_whitespace() {
                  declared.fetch.push(host.parse()?);
               }
            },
            "stores" => _ = declared.whole.insert(Namespace::Stores),
            "messages" => _ = declared.whole.insert(Namespace::Messages),
            "bridge" => _ = declared.whole.insert(Namespace::Bridge),
            "ui-tree" => _ = declared.whole.insert(Namespace::UiTree),
            _ => {},
         }
      }
      Ok(Self::Declared(declared))
   }
}

impl FromStr for Route {
   type Err = PermissionError;

   fn from_str(value: &str) -> Result<Self, Self::Err> {
      let invalid = || PermissionError::Route(value.to_owned());
      let (method, path) = value.split_once(' ').ok_or_else(invalid)?;
      let path = path.trim().strip_prefix('/').ok_or_else(invalid)?;
      let parts = path.split('/').collect::<Vec<_>>();
      let segments = parts
         .iter()
         .enumerate()
         .map(|(index, part)| {
            match *part {
               "**" if index + 1 == parts.len() => Ok(Segment::Rest),
               "**" => Err(PermissionError::Rest(value.to_owned())),
               "*" => Ok(Segment::Any),
               literal => Ok(Segment::Literal(literal.to_owned())),
            }
         })
         .collect::<Result<_, _>>()?;
      Ok(Self {
         method: (method != "*").then(|| method.to_ascii_uppercase()),
         segments,
      })
   }
}

impl Route {
   fn matches(&self, method: &str, path: &str) -> bool {
      if self
         .method
         .as_ref()
         .is_some_and(|expected| !method.eq_ignore_ascii_case(expected))
      {
         return false;
      }
      let path = path.split(['?', '#']).next().unwrap_or(path);
      let Some(path) = path.strip_prefix('/') else {
         return false;
      };
      let lower = path.to_ascii_lowercase();
      if ["\\", "%2f", "%5c"]
         .iter()
         .any(|slash| lower.contains(slash))
      {
         return false;
      }
      let dots = |part: &str| {
         let decoded = part.replace("%2e", ".");
         decoded == "." || decoded == ".."
      };
      if lower.split('/').any(dots) {
         return false;
      }
      let mut parts = path.split('/');
      for segment in &self.segments {
         match (segment, parts.next()) {
            (Segment::Rest, _) => return true,
            (Segment::Any, Some(part)) if !part.is_empty() => {},
            (Segment::Literal(literal), Some(part)) if literal == part => {},
            _ => return false,
         }
      }
      parts.next().is_none()
   }
}

impl FromStr for Host {
   type Err = PermissionError;

   fn from_str(value: &str) -> Result<Self, Self::Err> {
      let host = value.to_ascii_lowercase();
      let (under, name) = host
         .strip_prefix("*.")
         .map_or((false, host.as_str()), |name| (true, name));
      let valid = name.contains('.')
         && name.split('.').all(|label| {
            !label.is_empty()
               && label
                  .bytes()
                  .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
         });
      if !valid {
         return Err(PermissionError::Host(value.to_owned()));
      }
      let name = name.to_owned();
      Ok(if under {
         Self::Under(name)
      } else {
         Self::Exact(name)
      })
   }
}

impl Host {
   fn matches(&self, host: &str) -> bool {
      match self {
         Self::Exact(name) => host == name,
         Self::Under(name) => {
            host
               .strip_suffix(name.as_str())
               .is_some_and(|sub| sub.len() > 1 && sub.ends_with('.'))
         },
      }
   }
}

impl Permissions {
   /// What the plugin declared. The console declares nothing.
   #[must_use]
   pub fn grants(&self) -> Vec<Grant> {
      let Self::Declared(declared) = self else {
         return Vec::new();
      };
      let mut grants = Vec::new();
      if !declared.gateway.is_empty() {
         grants.push(Grant::Events(declared.gateway.iter().cloned().collect()));
      }
      if !declared.gateway_send.is_empty() {
         grants.push(Grant::GatewaySend(
            declared.gateway_send.iter().copied().collect(),
         ));
      }
      grants.extend(
         declared
            .discord
            .iter()
            .map(|route| Grant::Discord(route.to_string())),
      );
      if !declared.fetch.is_empty() {
         grants.push(Grant::Fetch(
            declared.fetch.iter().map(Host::to_string).collect(),
         ));
      }
      grants.extend(declared.whole.iter().map(|namespace| {
         match namespace {
            Namespace::Stores => Grant::Stores,
            Namespace::Messages => Grant::Messages,
            Namespace::Bridge => Grant::Bridge,
            Namespace::UiTree => Grant::UiTree,
         }
      }));
      grants
   }

   #[must_use]
   pub fn event(&self, name: &str) -> bool {
      match self {
         Self::Console => true,
         Self::Declared(declared) => declared.gateway.contains(name),
      }
   }

   #[must_use]
   pub fn gateway_send(&self, op: u32) -> bool {
      match self {
         Self::Console => true,
         Self::Declared(declared) => declared.gateway_send.contains(&op),
      }
   }

   #[must_use]
   pub fn discord(&self, method: &str, path: &str) -> bool {
      match self {
         Self::Console => true,
         Self::Declared(declared) => {
            declared
               .discord
               .iter()
               .any(|route| route.matches(method, path))
         },
      }
   }

   #[must_use]
   pub fn fetch(&self, url: &str) -> bool {
      match self {
         Self::Console => true,
         Self::Declared(declared) => {
            url_hosts(url).is_some_and(|found| {
               found.iter().all(|host| {
                  matches!(host, UrlHost::Named(name)
                     if declared.fetch.iter().any(|allowed| allowed.matches(name)))
               })
            })
         },
      }
   }

   #[must_use]
   pub fn stores(&self) -> bool {
      self.whole(Namespace::Stores)
   }

   #[must_use]
   pub fn messages(&self) -> bool {
      self.whole(Namespace::Messages)
   }

   #[must_use]
   pub fn bridge(&self) -> bool {
      self.whole(Namespace::Bridge)
   }

   #[must_use]
   pub fn ui_tree(&self) -> bool {
      self.whole(Namespace::UiTree)
   }

   fn whole(&self, namespace: Namespace) -> bool {
      match self {
         Self::Console => true,
         Self::Declared(declared) => declared.whole.contains(&namespace),
      }
   }

   /// Whether the plugin may point Discord at `host`.
   #[must_use]
   pub fn host(&self, host: &str) -> bool {
      match self {
         Self::Console => true,
         Self::Declared(declared) => {
            discord_host(host) || declared.fetch.iter().any(|allowed| allowed.matches(host))
         },
      }
   }

   /// The first host in `found` the plugin may not point Discord at.
   fn refused<'found>(&self, found: &'found BTreeSet<UrlHost>) -> Option<&'found UrlHost> {
      found.iter().find(|host| {
         match host {
            UrlHost::Named(name) => !self.host(name),
            UrlHost::Unreadable => !matches!(self, Self::Console),
         }
      })
   }

   /// Whether the plugin may draw an image from `uri`. Names like
   /// `res://ic_mana_id` and inline SVG paths load nothing.
   #[must_use]
   pub fn image(&self, uri: &str) -> bool {
      let lower = uri.trim_start().to_ascii_lowercase();
      if !["http:", "https:", "//"]
         .iter()
         .any(|scheme| lower.starts_with(scheme))
      {
         return true;
      }
      let mut links = Links::default();
      links.plain(uri);
      !links.0.is_empty() && links.0.values().all(|found| self.refused(found).is_none())
   }

   /// The first host a URL in `after` reaches that the plugin may not point
   /// Discord at, unless `before` spelled the same URL or one it trims down to.
   #[must_use]
   pub fn added(&self, before: &Links, after: &Links) -> Option<UrlHost> {
      self.foreign(after, |url| {
         before.0.contains_key(url) || before.urls().any(|original| trimmed(original, url))
      })
   }

   /// The first host a URL in `links` reaches that the plugin may not point
   /// Discord at, among the URLs `known` does not vouch for.
   #[must_use]
   pub fn foreign(&self, links: &Links, known: impl Fn(&str) -> bool) -> Option<UrlHost> {
      links
         .0
         .iter()
         .filter(|(url, _)| !known(url))
         .find_map(|(_, found)| self.refused(found))
         .cloned()
   }

   /// What `newer` declares that this does not, so an update cannot widen
   /// what a plugin reaches unasked.
   #[must_use]
   pub fn widened(&self, newer: &Self) -> Vec<String> {
      let (Self::Declared(old), Self::Declared(new)) = (self, newer) else {
         return Vec::new();
      };
      let routes = old
         .discord
         .iter()
         .map(Route::to_string)
         .collect::<BTreeSet<_>>();
      let hosts = old
         .fetch
         .iter()
         .map(Host::to_string)
         .collect::<BTreeSet<_>>();
      let mut added = Vec::new();
      added.extend(
         new.gateway
            .difference(&old.gateway)
            .map(|event| format!("@gateway {event}")),
      );
      added.extend(
         new.gateway_send
            .difference(&old.gateway_send)
            .map(|op| format!("@gateway-send {op}")),
      );
      added.extend(
         new.discord
            .iter()
            .map(Route::to_string)
            .filter(|route| !routes.contains(route))
            .map(|route| format!("@discord {route}")),
      );
      added.extend(
         new.fetch
            .iter()
            .map(Host::to_string)
            .filter(|host| !hosts.contains(host))
            .map(|host| format!("@fetch {host}")),
      );
      added.extend(
         new.whole
            .difference(&old.whole)
            .map(|namespace| format!("@{}", namespace.key())),
      );
      added
   }
}
