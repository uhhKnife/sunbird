export default {
   description: "Stops your replies from pinging the person you reply to",
   version: "0.1.1",
   author: "amaanq",
   permissions: {
      discord: ["POST /channels/*/messages"],
   },
} satisfies Phoenix.Manifest;
