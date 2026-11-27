export default {
   description: "Keeps deleted messages and edit history",
   version: "0.3.1",
   author: "amaanq",
   permissions: {
      gateway: ["messageCreate", "messageUpdate", "messageDelete", "messageDeleteBulk"],
      discord: ["GET /channels/*/messages", "DELETE /channels/*/messages/*"],
   },
} satisfies Phoenix.Manifest;
