#[path = "winres.rs"] mod winres;

fn main() {
   winres::embed(
      winres::Kind::Dll,
      "phoenix.dll",
      "Sunbird runtime for Discord Phoenix",
      None,
   );
}
