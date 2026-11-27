export default {
   description: "Replaces YouTube titles and thumbnails in embeds using DeArrow",
   version: "0.2.1",
   author: "amaanq",
   permissions: {
      gateway: ["messageCreate", "messageUpdate"],
      discord: ["GET /channels/*/messages"],
      fetch: ["sponsor.ajay.app", "dearrow-thumb.ajay.app"],
   },
} satisfies Phoenix.Manifest;
