fn main() {
   // GNU ld omits the note unless asked. sigs keys its build table on it, as
   // for Phoenix. Apple's ld64 does not accept `--build-id` and emits LC_UUID
   // by default.
   if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() != Ok("apple") {
      println!("cargo:rustc-cdylib-link-arg=-Wl,--build-id=sha1");
   }
}
