pub mod background;
mod hooks;
pub mod http;
mod intercept;
mod lockdown;
pub mod messages;
mod settings;
mod storage;

use std::{
   borrow::Cow,
   cell::{
      Cell,
      RefCell,
   },
   collections::{
      BTreeMap,
      BTreeSet,
      HashMap,
      HashSet,
   },
   fs,
   hash::{
      BuildHasher,
      RandomState,
   },
   io::ErrorKind,
   sync::{
      Arc,
      atomic::{
         AtomicU64,
         Ordering,
      },
   },
   time::{
      Duration,
      Instant,
   },
};

use log::Level;
use phoenix_sigs::registry::{
   EventId,
   GatewayRegistry,
};
use rquickjs::{
   CatchResultExt,
   CaughtError,
   Context,
   Ctx,
   Exception,
   Function,
   JsLifetime,
   Object,
   Runtime,
   Value,
   function::{
      Opt,
      Rest,
   },
};

use crate::{
   Chosen,
   Error,
   Header,
   Plugin,
   PluginInfo,
   PluginState,
   STATE,
   Setting,
   State,
   discord,
   gateway,
   io_error,
   js::{
      hooks::{
         Hook,
         add_gateway_api,
         gateway_object,
      },
      http::{
         discord_object,
         start_fetch,
      },
      lockdown::lockdown,
      messages::messages_object,
      settings::{
         Definition,
         settings_object,
      },
      storage::{
         storage,
         stores_object,
      },
   },
   permissions::{
      Links,
      Permissions,
      UrlHost,
      url_host,
   },
   update::outdated,
};

/// How long one plugin callback or promise job runs before `QuickJS`
/// interrupts it. The hooks run on Discord's own threads, so a spinning plugin
/// freezes the app for this long.
const BUDGET: Duration = Duration::from_secs(1);

/// The heap every plugin shares. Past it allocations throw, so a runaway
/// plugin fails before Android kills Discord for its memory.
const HEAP_LIMIT: usize = 128 << 20;

/// Drains in a row that may run out of budget before [`Engine::starve`] runs.
const OVERRUNS: u32 = 3;

const SEEN_URLS: usize = 32_768;

/// The exact URLs Discord's own payloads carried. Anyone can post a link, so a
/// host seen once vouches for nothing, and a plugin may hand back only a URL
/// Discord sent. Kept by keyed hash in two generations of [`SEEN_URLS`], so a
/// flood ages old URLs out without locking new ones out.
#[derive(Default)]
struct SeenUrls {
   keys:     RandomState,
   current:  HashSet<u64>,
   previous: HashSet<u64>,
}

impl SeenUrls {
   fn insert(&mut self, url: &str) {
      if self.current.len() >= SEEN_URLS {
         self.previous = std::mem::take(&mut self.current);
      }
      self.current.insert(self.keys.hash_one(url));
   }

   fn contains(&self, url: &str) -> bool {
      let key = self.keys.hash_one(url);
      self.current.contains(&key) || self.previous.contains(&key)
   }
}

/// The name the debug shell's `phoenix` object goes by, which no plugin may
/// take, since grants are looked up by name.
const CONSOLE: &str = "console";

pub struct Engine {
   runtime:  Runtime,
   context:  Context,
   /// The debug shell's prompt, a realm of its own so its unrestricted
   /// `phoenix` never sits in the plugins' frozen globals.
   console:  Context,
   budget:   Arc<Budget>,
   /// Drains in a row that ran out of budget with jobs left.
   overruns: Cell<u32>,
   plugins:  BTreeMap<String, Loaded>,
}

/// The deadline `QuickJS`'s interrupt handler checks, which every entry into
/// the engine and every plugin callback pushes out to [`BUDGET`] from now.
struct Budget {
   origin:   Instant,
   deadline: AtomicU64,
}

impl Budget {
   fn nanos(&self) -> u64 {
      u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
   }

   fn restart(&self) {
      let budget = u64::try_from(BUDGET.as_nanos()).unwrap_or(u64::MAX);
      self
         .deadline
         .store(self.nanos().saturating_add(budget), Ordering::Relaxed);
   }

   fn spent(&self) -> bool {
      self.nanos() > self.deadline.load(Ordering::Relaxed)
   }
}

struct Loaded {
   source: String,
   origin: Origin,
   state:  PluginState,
}

enum Origin {
   Bundled,
   /// Read from `home/plugins`, so the user can delete it.
   Installed,
   /// Installed over a bundled plugin, whose source is put back when the copy
   /// is uninstalled.
   Replacing(String),
}

impl Loaded {
   const fn new(source: String, origin: Origin) -> Self {
      Self {
         source,
         origin,
         state: PluginState::Off,
      }
   }

   fn install(&mut self, source: String) {
      let old = std::mem::replace(&mut self.source, source);
      if matches!(self.origin, Origin::Bundled) {
         self.origin = Origin::Replacing(old);
      }
   }
}

type ChosenMap = BTreeMap<String, BTreeMap<String, Chosen>>;

/// Which plugins the user turned off or on against their default and how
/// they set each plugin's settings, kept in `home/plugins.json`.
#[derive(serde::Serialize, serde::Deserialize)]
struct Choices<'a> {
   #[serde(default)]
   disabled:     BTreeSet<String>,
   #[serde(default)]
   enabled:      BTreeSet<String>,
   #[serde(default)]
   settings:     Cow<'a, ChosenMap>,
   #[serde(default)]
   staff:        bool,
   #[serde(default)]
   remote_shell: bool,
}

impl Default for Choices<'_> {
   fn default() -> Self {
      Self {
         disabled:     BTreeSet::new(),
         enabled:      BTreeSet::new(),
         settings:     Cow::Owned(BTreeMap::new()),
         staff:        false,
         remote_shell: false,
      }
   }
}

pub enum Before {
   Keep,
   Drop,
   Replace(String),
}

/// What plugins registered, kept in the runtime's userdata next to the
/// platform's own.
///
/// Callbacks stay JS values owned by the runtime, and the only thing plugins
/// can reach is their own `phoenix` object.
pub struct Registry<'js> {
   budget:             Arc<Budget>,
   handles:            Vec<(EventId, String, Object<'js>)>,
   hooks:              RefCell<HashMap<EventId, Vec<Hook<'js>>>>,
   defined:            RefCell<BTreeMap<String, Vec<Definition<'js>>>>,
   /// Kept across unloads, so a reloaded plugin sees what the user chose.
   chosen:             RefCell<ChosenMap>,
   /// `phoenix.onUnload` callbacks, run when the plugin is turned off,
   /// reloaded or removed.
   unloads:            RefCell<HashMap<String, Vec<Function<'js>>>>,
   /// The resolve and reject of each promise a worker thread will settle, by
   /// id.
   pending:            RefCell<HashMap<u64, (Function<'js>, Function<'js>)>>,
   /// `phoenix.discord.onRequest` interceptors, by id.
   request_hooks:      RefCell<HashMap<u64, (String, Function<'js>)>>,
   /// `phoenix.discord.onResponse` interceptors, by id.
   response_hooks:     RefCell<HashMap<u64, (String, Function<'js>)>>,
   gateway_send_hooks: RefCell<HashMap<u64, (String, Function<'js>)>>,
   /// What each loaded plugin may reach, for the checks platform code makes by
   /// plugin name.
   granted:            RefCell<HashMap<String, Arc<Permissions>>>,
   seen:               RefCell<SeenUrls>,
   /// `phoenix.messages.onSend` interceptors in registration order, by id.
   pub interceptors:   RefCell<Vec<(u64, String, Function<'js>)>>,
}

// SAFETY: every field is bound to 'js, and Changed swaps exactly that lifetime.
unsafe impl<'js> JsLifetime<'js> for Registry<'js> {
   type Changed<'to> = Registry<'to>;
}

/// A plugin's source as the body of a function of its `phoenix` object.
///
/// The realm's `Function` constructor parses it as a function body, so the
/// source cannot close the function early and declare script-level bindings
/// every other plugin's free names would resolve to.
pub fn compile<'js>(ctx: &Ctx<'js>, source: &str) -> rquickjs::Result<Function<'js>> {
   ctx.globals()
      .get::<_, Function<'js>>("Function")?
      .call(("phoenix", source))
}

#[expect(clippy::needless_pass_by_value, reason = "used as a map_err callback")]
#[must_use]
pub fn js_error(err: CaughtError<'_>) -> Error {
   Error::Js(err.to_string())
}

#[must_use]
pub fn throw(ctx: &Ctx<'_>, err: &Error) -> rquickjs::Error {
   Exception::throw_message(ctx, &err.to_string())
}

fn state() -> &'static State {
   STATE
      .get()
      .expect("natives run after start() publishes the state")
}

impl Engine {
   pub fn new(events: &GatewayRegistry) -> Result<Self, Error> {
      let runtime = Runtime::new().map_err(|err| Error::Js(err.to_string()))?;
      runtime.set_max_stack_size(512 * 1024);
      runtime.set_memory_limit(HEAP_LIMIT);
      let budget = Arc::new(Budget {
         origin:   Instant::now(),
         deadline: AtomicU64::new(0),
      });
      let watched = Arc::clone(&budget);
      runtime.set_interrupt_handler(Some(Box::new(move || watched.spent())));
      let context = Context::full(&runtime).map_err(|err| Error::Js(err.to_string()))?;
      let console = Context::full(&runtime).map_err(|err| Error::Js(err.to_string()))?;
      budget.restart();
      context.with(|ctx| {
         let registry = registry(&ctx, events, Arc::clone(&budget))
            .catch(&ctx)
            .map_err(js_error)?;
         let handles = registry
            .handles
            .iter()
            .map(|(.., handle)| handle.clone().into_value())
            .collect();
         ctx.store_userdata(registry)
            .map_err(|err| Error::Js(err.to_string()))?;
         if let Some(platform) = crate::platform() {
            platform.init(&ctx).catch(&ctx).map_err(js_error)?;
         }
         lockdown(&ctx, handles).catch(&ctx).map_err(js_error)
      })?;
      Ok(Self {
         runtime,
         context,
         console,
         budget,
         overruns: Cell::new(0),
         plugins: BTreeMap::new(),
      })
   }

   /// Runs `work` in the engine's context, then the promise reactions it
   /// queued.
   pub fn with<R>(&self, work: impl FnOnce(Ctx<'_>) -> R) -> R {
      self.budget.restart();
      let result = self.context.with(work);
      self.drain();
      result
   }

   /// Runs promise reactions until none are left. `QuickJS` queues them, and
   /// nothing else runs the queue. They share one budget, and the jobs left
   /// when it runs out wait for the next entry. Only a queue still growing
   /// after [`OVERRUNS`] entries is starved, since starving fails every
   /// plugin's pending jobs.
   fn drain(&self) {
      self.budget.restart();
      while !self.budget.spent() {
         match self.runtime.execute_pending_job() {
            Ok(true) => {},
            Ok(false) => {
               self.overruns.set(0);
               return;
            },
            Err(err) => log::error!("a promise job threw: {err}"),
         }
      }
      let overruns = self.overruns.get() + 1;
      if overruns < OVERRUNS {
         self.overruns.set(overruns);
         log::warn!("promise jobs ran past {BUDGET:?}, the rest wait for the next call");
         return;
      }
      self.overruns.set(0);
      self.starve();
   }

   /// Runs out the queue with every allocation failing. A job that would
   /// queue another cannot, so the queue only shrinks, where a promise that
   /// queues two more on every run would outgrow the budget forever. A cap at
   /// the heap's current size let each job reuse what the last one freed.
   fn starve(&self) {
      self.runtime.set_memory_limit(1);
      let mut failed = 0_u64;
      loop {
         match self.runtime.execute_pending_job() {
            Ok(true) => {},
            Ok(false) => break,
            Err(_) => failed += 1,
         }
      }
      self.runtime.set_memory_limit(HEAP_LIMIT);
      log::error!("promise jobs ran past {BUDGET:?}, {failed} more failed to finish");
   }

   #[must_use]
   pub fn source(&self, name: &str) -> Option<String> {
      self.plugins.get(name).map(|loaded| loaded.source.clone())
   }

   /// The bundled copy an installed one replaced.
   #[must_use]
   pub fn bundled(&self, name: &str) -> Option<String> {
      match &self.plugins.get(name)?.origin {
         Origin::Replacing(bundled) => Some(bundled.clone()),
         Origin::Bundled | Origin::Installed => None,
      }
   }

   #[must_use]
   pub fn plugins(&self) -> Vec<PluginInfo> {
      self.with(|ctx| {
         let registry = ctx.userdata::<Registry<'_>>();
         let defined = registry.as_ref().map(|registry| registry.defined.borrow());
         let chosen = registry.as_ref().map(|registry| registry.chosen.borrow());
         self
            .plugins
            .iter()
            .map(|(name, loaded)| {
               let settings = defined
                  .as_ref()
                  .and_then(|defined| defined.get(name))
                  .into_iter()
                  .flatten()
                  .map(|definition| {
                     let picked = chosen
                        .as_ref()
                        .and_then(|chosen| chosen.get(name)?.get(&definition.key));
                     Setting {
                        key:         definition.key.clone(),
                        title:       definition.title.clone(),
                        description: definition.description.clone(),
                        control:     definition.kind.current(picked),
                        multiline:   definition.multiline,
                     }
                  })
                  .collect();
               PluginInfo {
                  name: name.clone(),
                  state: loaded.state.clone(),
                  installed: !matches!(loaded.origin, Origin::Bundled),
                  header: Header::from(loaded.source.as_str()),
                  settings,
                  permissions: loaded
                     .source
                     .parse::<Permissions>()
                     .map_or_else(|_| Vec::new(), |permissions| permissions.grants()),
               }
            })
            .collect()
      })
   }

   /// Evaluates `name` with a fresh `phoenix` object, recording any error.
   fn eval(&mut self, name: &str) {
      let Some(loaded) = self.plugins.get(name) else {
         return;
      };
      let source = loaded.source.as_str();
      let outcome = (name != CONSOLE)
         .then_some(source)
         .ok_or_else(|| Error::Js(format!("the name {CONSOLE} belongs to the debug shell")))
         .and_then(|source| {
            if let Some(min) = Header::from(source).min_sunbird.filter(|min| outdated(min)) {
               return Err(Error::Js(format!(
                  "needs Sunbird {min}, update Phoenix Unlock first"
               )));
            }
            source
               .parse::<Permissions>()
               .map_err(|err| Error::Js(err.to_string()))
         })
         .and_then(|permissions| {
            let permissions = Arc::new(permissions);
            self.with(|ctx| {
               let run = || -> rquickjs::Result<()> {
                  let phoenix = api(&ctx, name, &permissions)?;
                  compile(&ctx, source)?.call((phoenix,))
               };
               run().catch(&ctx).map_err(js_error)
            })
         });
      let Some(loaded) = self.plugins.get_mut(name) else {
         return;
      };
      match outcome {
         Ok(()) => {
            log::info!("loaded plugin {name}");
            loaded.state = PluginState::On;
         },
         Err(err) => {
            log::error!("plugin {name} failed to load: {err}");
            loaded.state = PluginState::Failed(err.to_string());
         },
      }
   }

   /// Drops every hook `name` registered, and turns off events nobody else
   /// listens to.
   pub(super) fn unload(&self, name: &str) {
      self.with(|ctx| {
         let Some(registry) = ctx.userdata::<Registry<'_>>() else {
            return;
         };
         let cleanups = registry
            .unloads
            .borrow_mut()
            .remove(name)
            .unwrap_or_default();
         for cleanup in cleanups {
            if let Err(err) = cleanup.call::<_, ()>(()).catch(&ctx) {
               log::error!("[{name}] onUnload: {err}");
            }
         }
         registry.defined.borrow_mut().remove(name);
         registry.granted.borrow_mut().remove(name);
         registry
            .request_hooks
            .borrow_mut()
            .retain(|_, (plugin, _)| plugin != name);
         discord::forget_request_hooks(name);
         registry
            .response_hooks
            .borrow_mut()
            .retain(|_, (plugin, _)| plugin != name);
         discord::forget_response_hooks(name);
         registry
            .gateway_send_hooks
            .borrow_mut()
            .retain(|_, (plugin, _)| plugin != name);
         gateway::forget_send_hooks(name);
         registry
            .interceptors
            .borrow_mut()
            .retain(|(_, plugin, _)| plugin != name);
         if let Some(platform) = crate::platform() {
            platform.unload(&ctx, name);
         }
         let mut hooks = registry.hooks.borrow_mut();
         for (event, list) in hooks.iter_mut() {
            list.retain(|hook| hook.plugin != name);
            if list.is_empty() {
               gateway::uninstall(*event);
            }
         }
         hooks.retain(|_, list| !list.is_empty());
      });
   }

   pub fn set_enabled(&mut self, name: &str, enabled: bool) {
      let Some(loaded) = self.plugins.get_mut(name) else {
         return;
      };
      if loaded.state.is_on() == enabled {
         return;
      }
      loaded.state = PluginState::from_switch(enabled);
      if enabled {
         self.eval(name);
      } else {
         self.unload(name);
      }
      self.save_choices();
   }

   /// Adds `name` or replaces its source, then runs it unless the user turned
   /// it off.
   pub fn install(&mut self, name: &str, source: String) {
      let enabled = if let Some(loaded) = self.plugins.get_mut(name) {
         loaded.install(source);
         loaded.state.is_on()
      } else {
         let mut loaded = Loaded::new(source, Origin::Installed);
         loaded.state = PluginState::On;
         self.plugins.insert(name.to_owned(), loaded);
         true
      };
      if enabled {
         self.unload(name);
         self.eval(name);
      }
   }

   /// Drops `name` and what the user chose for it, or, when it replaced a
   /// bundled plugin, puts that one back with the same switch and settings.
   pub fn uninstall(&mut self, name: &str) -> crate::Uninstalled {
      self.unload(name);
      let restored = self.plugins.get_mut(name).and_then(|loaded| {
         let Origin::Replacing(bundled) = std::mem::replace(&mut loaded.origin, Origin::Bundled)
         else {
            return None;
         };
         loaded.source = bundled;
         loaded.state = PluginState::from_switch(loaded.state.is_on());
         Some(loaded.state.is_on())
      });
      let outcome = if let Some(enabled) = restored {
         if enabled {
            self.eval(name);
         }
         crate::Uninstalled::RestoredBundled
      } else {
         self.plugins.remove(name);
         self.with(|ctx| {
            if let Some(registry) = ctx.userdata::<Registry<'_>>() {
               registry.chosen.borrow_mut().remove(name);
            }
         });
         crate::Uninstalled::Removed
      };
      self.save_choices();
      outcome
   }

   pub fn reload(&mut self, name: &str) {
      if self
         .plugins
         .get(name)
         .is_some_and(|loaded| loaded.state.is_on())
      {
         self.unload(name);
         self.eval(name);
      }
   }

   pub fn save_choices(&self) {
      let (mut disabled, mut enabled) = (BTreeSet::new(), BTreeSet::new());
      for (name, loaded) in &self.plugins {
         if Header::from(loaded.source.as_str()).default_off {
            if loaded.state.is_on() {
               enabled.insert(name.clone());
            }
         } else if !loaded.state.is_on() {
            disabled.insert(name.clone());
         }
      }
      let remote_shell = crate::remote_shell_enabled();
      let json = self.with(|ctx| {
         let registry = ctx.userdata::<Registry<'_>>();
         let chosen = registry.as_ref().map(|registry| registry.chosen.borrow());
         let empty = BTreeMap::new();
         serde_json::to_vec(&Choices {
            disabled,
            enabled,
            settings: Cow::Borrowed(chosen.as_deref().unwrap_or(&empty)),
            staff: crate::staff_enabled(),
            remote_shell,
         })
      });
      let path = state().choices_path();
      let write = || -> std::io::Result<()> {
         fs::create_dir_all(path.parent().expect("the choices path has a parent"))?;
         fs::write(&path, json?)
      };
      if let Err(err) = write() {
         log::error!("{}: {err}", path.display());
      }
   }

   /// The result as JSON when it has a JSON form, else as `String(result)`.
   /// The prompt sees a `phoenix` object of its own, named "console".
   pub fn evaluate(&self, code: &str) -> Result<String, Error> {
      self.budget.restart();
      let result = self.console.with(|ctx| {
         let run = || -> rquickjs::Result<String> {
            if !ctx.globals().contains_key("phoenix")? {
               let phoenix = api(&ctx, CONSOLE, &Arc::new(Permissions::Console))?;
               if let Some(platform) = crate::platform() {
                  platform.console(&ctx, &phoenix)?;
               }
               ctx.globals().set("phoenix", phoenix)?;
            }
            let result = ctx.eval::<Value<'_>, _>(code)?;
            if let Some(text) = result.as_string() {
               return text.to_string();
            }
            match ctx.json_stringify(result.clone())? {
               Some(json) => json.to_string(),
               None => {
                  ctx.globals()
                     .get::<_, Function<'_>>("String")?
                     .call((result,))
               },
            }
         };
         run().catch(&ctx).map_err(js_error)
      });
      self.drain();
      result
   }
}

/// What `plugin` may reach, `None` for a plugin not loaded.
#[must_use]
pub fn granted(ctx: &Ctx<'_>, plugin: &str) -> Option<Arc<Permissions>> {
   ctx.userdata::<Registry<'_>>()
      .and_then(|registry| registry.granted.borrow().get(plugin).cloned())
}

/// Whether `plugin` may draw an image from `uri`, false for a plugin not
/// loaded.
#[must_use]
pub fn image_allowed(ctx: &Ctx<'_>, plugin: &str, uri: &str) -> bool {
   granted(ctx, plugin).is_some_and(|permissions| permissions.image(uri))
}

/// Whether `plugin`'s rewrite of `before` into `after` adds a URL reaching a
/// host it may not point Discord at, logging the refusal.
#[must_use]
pub fn rewrite_refused(
   ctx: &Ctx<'_>,
   plugin: &str,
   what: &str,
   before: &Links,
   after: &Links,
) -> bool {
   let Some(host) = granted(ctx, plugin).map_or(Some(UrlHost::Unreadable), |permissions| {
      permissions.added(before, after)
   }) else {
      return false;
   };
   log::error!("[{plugin}] {what}: dropped a rewrite adding {host}, not on its // @fetch line");
   true
}

/// Remembers the URLs in a payload from Discord.
pub fn saw(ctx: &Ctx<'_>, links: &Links) {
   if let Some(registry) = ctx.userdata::<Registry<'_>>() {
      let mut seen = registry.seen.borrow_mut();
      for url in links.urls() {
         seen.insert(url);
      }
   }
}

/// The first host a URL in `payload` reaches that `plugin` may not hand
/// Discord, since neither its grants nor Discord's own payloads vouch for it.
#[must_use]
pub fn foreign_host(ctx: &Ctx<'_>, plugin: &str, payload: &str) -> Option<UrlHost> {
   let (Some(permissions), Some(registry)) = (granted(ctx, plugin), ctx.userdata::<Registry<'_>>())
   else {
      return Some(UrlHost::Unreadable);
   };
   let seen = registry.seen.borrow();
   permissions.foreign(&Links::scan(payload), |url| seen.contains(url))
}

/// `icon` when `plugin` may draw it, else a `TypeError` naming the fix.
pub fn checked_icon(
   ctx: &Ctx<'_>,
   plugin: &str,
   icon: Option<String>,
) -> rquickjs::Result<Option<String>> {
   match icon {
      Some(uri) if !image_allowed(ctx, plugin, &uri) => {
         Err(Exception::throw_type(
            ctx,
            &format!(
               "{}: images load only from Discord's CDN or a host on the plugin's // @fetch line",
               url_host(&uri).as_deref().unwrap_or("icon")
            ),
         ))
      },
      icon => Ok(icon),
   }
}

/// Gives the plugin callback about to run a budget of its own, so one that
/// spins does not take the next plugin's time.
pub fn restart_budget(ctx: &Ctx<'_>) {
   if let Some(registry) = ctx.userdata::<Registry<'_>>() {
      registry.budget.restart();
   }
}

/// One handle per live registry entry, frozen by [`lockdown`]. Plugins compare
/// nothing and parse nothing, the runtime recognizes a handle by identity.
fn registry<'js>(
   ctx: &Ctx<'js>,
   events: &GatewayRegistry,
   budget: Arc<Budget>,
) -> rquickjs::Result<Registry<'js>> {
   let mut handles = Vec::new();
   for (event, entry) in events.iter() {
      let key = camel_case(&entry.name);
      let handle = Object::new(ctx.clone())?;
      let label = format!("gateway.{key}");
      handle.set(
         "toString",
         Function::new(ctx.clone(), move || label.clone())?,
      )?;
      handles.push((event, key, handle));
   }
   Ok(Registry {
      budget,
      handles,
      hooks: RefCell::default(),
      defined: RefCell::default(),
      chosen: RefCell::default(),
      unloads: RefCell::default(),
      pending: RefCell::default(),
      request_hooks: RefCell::default(),
      response_hooks: RefCell::default(),
      gateway_send_hooks: RefCell::default(),
      granted: RefCell::default(),
      seen: RefCell::default(),
      interceptors: RefCell::default(),
   })
}

/// `MESSAGE_CREATE` to `messageCreate`, the key plugins and `phoenix.d.ts` use.
fn camel_case(name: &str) -> String {
   name
      .split('_')
      .enumerate()
      .map(|(index, word)| {
         let lower = word.to_ascii_lowercase();
         let mut chars = lower.chars();
         match chars.next() {
            Some(first) if index > 0 => first.to_ascii_uppercase().to_string() + chars.as_str(),
            _ => lower,
         }
      })
      .collect()
}

/// The `phoenix` object one plugin receives, holding only what `permissions`
/// grants.
fn api<'js>(
   ctx: &Ctx<'js>,
   plugin: &str,
   permissions: &Arc<Permissions>,
) -> rquickjs::Result<Object<'js>> {
   ctx.userdata::<Registry<'js>>()
      .ok_or_else(|| Exception::throw_internal(ctx, "no registry"))?
      .granted
      .borrow_mut()
      .insert(plugin.to_owned(), Arc::clone(permissions));
   let api = Object::new(ctx.clone())?;
   api.set("gateway", gateway_object(ctx, plugin, permissions)?)?;

   add_gateway_api(ctx, plugin, &api, permissions)?;

   let messages = messages_object(ctx)?;
   if let Some(platform) = crate::platform() {
      platform.api(ctx, plugin, permissions, &api, &messages)?;
   }
   if permissions.messages() {
      api.set("messages", messages)?;
   }
   api.set("log", log_object(ctx, plugin)?)?;
   api.set("storage", storage(ctx, plugin)?)?;
   api.set("settings", settings_object(ctx, plugin)?)?;
   let name = plugin.to_owned();
   api.set(
      "onUnload",
      Function::new(ctx.clone(), move |ctx: Ctx<'js>, cleanup: Function<'js>| {
         ctx.userdata::<Registry<'js>>()
            .ok_or_else(|| Exception::throw_internal(&ctx, "no registry"))?
            .unloads
            .borrow_mut()
            .entry(name.clone())
            .or_default()
            .push(cleanup);
         Ok::<_, rquickjs::Error>(())
      })?,
   )?;
   if permissions.stores() {
      api.set("stores", stores_object(ctx)?)?;
   }
   api.set("discord", discord_object(ctx, plugin, permissions)?)?;
   let granted = Arc::clone(permissions);
   api.set(
      "fetch",
      Function::new(
         ctx.clone(),
         move |ctx: Ctx<'js>, url: String, init: Opt<Object<'js>>| {
            if !granted.fetch(&url) {
               return Err(Exception::throw_message(
                  &ctx,
                  &format!(
                     "{}: add this host to the plugin's // @fetch line",
                     url_host(&url).as_deref().unwrap_or("fetch")
                  ),
               ));
            }
            start_fetch(&ctx, url, init.0)
         },
      )?,
   )?;
   Ok(api)
}

/// `phoenix.log`, whose lines carry the plugin's name.
fn log_object<'js>(ctx: &Ctx<'js>, plugin: &str) -> rquickjs::Result<Object<'js>> {
   let log = Object::new(ctx.clone())?;
   for (method, level) in [
      ("debug", Level::Debug),
      ("info", Level::Info),
      ("warn", Level::Warn),
      ("error", Level::Error),
   ] {
      let name = plugin.to_owned();
      log.set(
         method,
         Function::new(ctx.clone(), move |ctx: Ctx<'js>, args: Rest<Value<'js>>| {
            let parts = args
               .0
               .into_iter()
               .map(|arg| {
                  if let Some(text) = arg.as_string() {
                     return text.to_string();
                  }
                  ctx.json_stringify(arg)?
                     .map_or_else(|| Ok("undefined".to_owned()), |json| json.to_string())
               })
               .collect::<rquickjs::Result<Vec<_>>>()?;
            log::log!(level, "[{name}] {}", parts.join(" "));
            Ok::<_, rquickjs::Error>(())
         })?,
      )?;
   }
   Ok(log)
}

/// Evaluates `bundled` plus every `*.js` file in the plugins directory, in name
/// order, skipping the ones the user turned off.
#[expect(
   clippy::significant_drop_tightening,
   reason = "plugins load under one engine lock so no gateway event sees a half-loaded set"
)]
pub fn load_plugins(state: &'static State, bundled: Vec<Plugin>) -> Result<Vec<String>, Error> {
   let choices_path = state.choices_path();
   let choices = match fs::read(&choices_path) {
      Ok(bytes) => {
         serde_json::from_slice::<Choices>(&bytes).unwrap_or_else(|err| {
            log::error!("{}: {err}", choices_path.display());
            Choices::default()
         })
      },
      Err(err) if err.kind() == ErrorKind::NotFound => Choices::default(),
      Err(err) => return Err(io_error(&choices_path)(err)),
   };
   crate::STAFF.store(choices.staff, std::sync::atomic::Ordering::Release);
   crate::set_remote_shell_flag(choices.remote_shell);
   if let Some(platform) = crate::platform() {
      platform.staff(&state.image);
   }

   let dir = state.plugins_dir();
   let mut plugins = bundled
      .into_iter()
      .map(|plugin| {
         (plugin.name, Loaded::new(plugin.source, Origin::Bundled))
      })
      .collect::<BTreeMap<String, Loaded>>();
   let paths = match fs::read_dir(&dir) {
      Ok(entries) => {
         entries
            .collect::<Result<Vec<_>, _>>()
            .map_err(io_error(&dir))?
      },
      Err(err) if err.kind() == ErrorKind::NotFound => Vec::new(),
      Err(err) => return Err(io_error(&dir)(err)),
   };
   for path in paths.iter().map(fs::DirEntry::path) {
      let Some(name) = path
         .file_stem()
         .and_then(|stem| stem.to_str())
         .filter(|_| path.extension().is_some_and(|ext| ext == "js"))
      else {
         continue;
      };
      let source = fs::read_to_string(&path).map_err(io_error(&path))?;
      match plugins.get_mut(name) {
         Some(loaded) => loaded.install(source),
         None => {
            plugins.insert(name.to_owned(), Loaded::new(source, Origin::Installed));
         },
      }
   }
   for (name, loaded) in &mut plugins {
      let enabled = if Header::from(loaded.source.as_str()).default_off {
         choices.enabled.contains(name)
      } else {
         !choices.disabled.contains(name)
      };
      loaded.state = PluginState::from_switch(enabled);
   }

   let mut engine = state
      .js
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner);
   engine.with(|ctx| {
      if let Some(registry) = ctx.userdata::<Registry<'_>>() {
         *registry.chosen.borrow_mut() = choices.settings.into_owned();
      }
   });
   engine.plugins = plugins;
   let enabled = engine
      .plugins
      .iter()
      .filter(|(_, loaded)| loaded.state.is_on())
      .map(|(name, _)| name.clone())
      .collect::<Vec<String>>();
   for name in &enabled {
      engine.eval(name);
   }
   Ok(enabled
      .into_iter()
      .filter(|name| {
         engine
            .plugins
            .get(name)
            .is_some_and(|loaded| matches!(loaded.state, PluginState::On))
      })
      .collect())
}
