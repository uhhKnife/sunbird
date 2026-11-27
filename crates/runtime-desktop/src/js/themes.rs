//! `phoenix.themes` on desktop: `.theme.css` themes through
//! [`crate::gpui_theme`], with the method names Android's themes use.

use std::{
   path::PathBuf,
   sync::{
      Mutex,
      PoisonError,
   },
};

use rquickjs::{
   Array,
   Ctx,
   Exception,
   Function,
   Object,
};

use crate::gpui_theme;

/// The plugin whose theme is showing, and the file it applied, so unloading
/// the plugin brings back Discord's colors.
static ACTIVE: Mutex<Option<(String, Option<String>)>> = Mutex::new(None);

fn themes_dir() -> PathBuf {
   phoenix_runtime::state().map_or_else(
      || PathBuf::from("themes"),
      |state| state.plugins_dir().with_file_name("themes"),
   )
}

fn set_active(active: Option<(String, Option<String>)>) {
   *ACTIVE.lock().unwrap_or_else(PoisonError::into_inner) = active;
}

pub fn unload(plugin: &str) {
   let mut active = ACTIVE.lock().unwrap_or_else(PoisonError::into_inner);
   if active.as_ref().is_some_and(|(owner, _)| owner == plugin) {
      *active = None;
      drop(active);
      gpui_theme::clear();
   }
}

pub fn object<'js>(ctx: &Ctx<'js>, plugin: &str) -> rquickjs::Result<Object<'js>> {
   let themes = Object::new(ctx.clone())?;
   themes.set(
      "supported",
      Function::new(ctx.clone(), gpui_theme::is_supported)?,
   )?;
   themes.set(
      "list",
      Function::new(
         ctx.clone(),
         |ctx: Ctx<'js>| -> rquickjs::Result<Array<'js>> {
            let active = ACTIVE
               .lock()
               .unwrap_or_else(PoisonError::into_inner)
               .as_ref()
               .and_then(|(_, file)| file.clone());
            let arr = Array::new(ctx.clone())?;
            for (i, theme) in gpui_theme::list(&themes_dir()).into_iter().enumerate() {
               let item = Object::new(ctx.clone())?;
               item.set("active", active.as_deref() == Some(theme.file.as_str()))?;
               item.set("id", theme.file)?;
               item.set("name", theme.name)?;
               item.set("authors", Array::new(ctx.clone())?)?;
               arr.set(i, item)?;
            }
            Ok(arr)
         },
      )?,
   )?;
   let owner = plugin.to_owned();
   themes.set(
      "apply",
      Function::new(ctx.clone(), move |ctx: Ctx<'js>, id: String| {
         // Only files inside the themes folder.
         let path = themes_dir().join(&id);
         if id.contains(['/', '\\', ':']) || !path.is_file() {
            return Err(Exception::throw_message(&ctx, &format!("no theme {id}")));
         }
         let css = std::fs::read_to_string(&path)
            .map_err(|err| Exception::throw_message(&ctx, &format!("reading {id}: {err}")))?;
         gpui_theme::set_css(&css);
         set_active(Some((owner.clone(), Some(id))));
         Ok(())
      })?,
   )?;
   let owner = plugin.to_owned();
   themes.set(
      "setCss",
      Function::new(ctx.clone(), move |css: String| {
         set_active(Some((owner.clone(), None)));
         gpui_theme::set_css(&css)
      })?,
   )?;
   themes.set(
      "clear",
      Function::new(ctx.clone(), || {
         set_active(None);
         gpui_theme::clear();
      })?,
   )?;
   themes.set(
      "openThemesDir",
      Function::new(ctx.clone(), || {
         let dir = themes_dir();
         std::thread::spawn(move || gpui_theme::open_dir(&dir));
      })?,
   )?;
   Ok(themes)
}
