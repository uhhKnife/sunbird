export default {
   description: "Sends messages without notifying anyone, always or when they start with a prefix",
   version: "1.0.1",
   author: "Lil Poop",
   permissions: {
      messages: true,
      discord: ["POST /channels/*/messages"],
   },
} satisfies Phoenix.Manifest;
