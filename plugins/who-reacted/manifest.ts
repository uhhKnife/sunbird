export default {
   description: "Lists the users behind normal and super reactions from the message menu",
   version: "1.0.0",
   author: "sh-ayu",
   permissions: {
      discord: ["GET /channels/*/messages/*", "GET /channels/*/messages/*/reactions/**"],
   },
} satisfies Phoenix.Manifest;
