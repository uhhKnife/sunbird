export default {
   description: "Shows which devices people are online from: desktop, mobile, web or console",
   version: "1.0.1",
   author: "yuax",
   permissions: {
      gateway: [
         "messageCreate",
         "presenceUpdate",
         "presencesReplace",
         "guildMembersChunk",
         "guildMemberListUpdate",
         "readySupplemental",
         "sessionsReplace",
      ],
      discord: ["GET /users/@me", "GET /users/*/profile"],
      fetch: ["assets.sunbird.tools"],
   },
} satisfies Phoenix.Manifest;
