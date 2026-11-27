export default {
   description: "Shows user badges from other Discord client mods on profiles",
   version: "0.5.8",
   author: "iFlex0x, wolfieeeeeeee",
   warning: "Fetches badges from Equibadges (badges.equicord.org)",
   permissions: {
      discord: ["GET /users/@me", "GET /users/*/profile", "GET /users/*/badges"],
      fetch: [
         "*.equicord.org",
         "badges.vencord.dev",
         "gb.obamabot.me",
         "nekocord.dev",
         "codeberg.org",
         "paicord.llsc12.me",
      ],
   },
} satisfies Phoenix.Manifest;
