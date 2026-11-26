use phoenix_hook::image::Image;
use phoenix_sigs::desktop::{
   WINDOWS_RESTART_SCRIPT,
   windows_restart_script,
};

// Older launchers append their parsed arguments verbatim to Discord's command
// line, so pass the original command line as one escaped argument. The marker
// lets an upgraded launcher recognize the same handoff.
const RESTART_SCRIPT: &str = r#"$oldPid = $env:ZED_RESTART_PID
$exePath = $env:ZED_RESTART_EXECUTABLE
$arguments = $env:ZED_RESTART_ARGUMENTS
foreach ($name in 'PID','EXECUTABLE','ARGUMENTS') {
    Remove-Item "Env:ZED_RESTART_$name" -ErrorAction SilentlyContinue
}
$launcher = $env:SUNBIRD_RESTART_EXE
$legacy = !$launcher
if ($legacy) { $launcher = "$env:LOCALAPPDATA\Sunbird\sunbird.exe" }
if (Test-Path -LiteralPath $launcher -PathType Leaf) {
    $exePath = $launcher
    if ($legacy) {
        $env:SUNBIRD_RESTART_ARGS = 'raw'
        $escaped = $arguments -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1'
        $arguments = '-- " ' + $escaped + '"'
    } else {
        $arguments = "$env:SUNBIRD_RESTART_ARGS $arguments"
    }
}
while (Get-Process -Id $oldPid -ErrorAction SilentlyContinue) {
    Start-Sleep -Seconds 0.1
}
$opts = @{}
if ($arguments) { $opts.ArgumentList = $arguments }
Start-Process -FilePath $exePath @opts
"#;

pub fn install(image: &Image<'static>) {
   let addr = match windows_restart_script(image) {
      Ok(addr) => addr,
      Err(err) => {
         log::warn!("could not redirect Discord restart: {err}");
         return;
      },
   };
   const {
      assert!(RESTART_SCRIPT.len() <= WINDOWS_RESTART_SCRIPT.len());
   }
   // GPUI passes the script as a Rust string slice, so keep its original length.
   let mut script = [b' '; WINDOWS_RESTART_SCRIPT.len()];
   script[..RESTART_SCRIPT.len()].copy_from_slice(RESTART_SCRIPT.as_bytes());
   // SAFETY: the locator matched the script and Discord has yet to start.
   if let Err(err) = unsafe { image.write_code(addr, &script) } {
      log::warn!("could not redirect Discord restart: {err}");
   }
}
