export default {
   description: "Adds a toggle to automatically spoiler everything you send",
   version: "1.2.2",
   author: "cmdr-chara",
   permissions: {
      discord: ["POST /channels/*/messages"],
      messages: true,
   },
} satisfies Phoenix.Manifest;
