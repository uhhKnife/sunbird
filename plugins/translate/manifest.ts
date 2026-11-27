export default {
   description: "Translates messages from the message menu, or every message in selected channels, using Kagi or Google",
   version: "0.3.1",
   author: "amaanq",
   permissions: {
      gateway: ["messageCreate"],
      fetch: ["translate-pa.googleapis.com", "translate.kagi.com"],
   },
} satisfies Phoenix.Manifest;
