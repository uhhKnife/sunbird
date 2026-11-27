export default {
   description: "Removes tracking parameters from links you send and receive",
   version: "0.1.3",
   author: "amaanq",
   permissions: {
      gateway: ["messageCreate", "messageUpdate"],
      messages: true,
   },
} satisfies Phoenix.Manifest;
