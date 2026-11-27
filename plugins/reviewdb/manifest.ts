export default {
   description: "Adds a ReviewDB tab to user profiles",
   version: "0.2.2",
   author: "mantikafasi",
   permissions: {
      discord: ["GET /users/@me", "GET /users/*", "POST /oauth2/authorize"],
      fetch: ["manti.vendicated.dev"],
   },
} satisfies Phoenix.Manifest;
