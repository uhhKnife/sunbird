export default {
   description: "Prevents Discord from sending typing indicators",
   version: "1.0.1",
   author: "mantikafasi",
   permissions: {
      discord: ["POST /channels/*/typing"],
   },
} satisfies Phoenix.Manifest;
