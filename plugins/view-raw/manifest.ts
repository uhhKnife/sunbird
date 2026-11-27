export default {
   description: "Opens a message's raw text and JSON in a viewer",
   version: "1.2.2",
   author: "cmdr-chara",
   permissions: {
      discord: ["GET /channels/*/messages"],
   },
} satisfies Phoenix.Manifest;
