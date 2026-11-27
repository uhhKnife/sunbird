export default {
   description: "Shows remaining timeout duration beside usernames",
   version: "0.1.1",
   author: "hakuxyz, port of Valenced \"Show Timeout Duration\" by Palm",
   permissions: {
      gateway: ["messageCreate", "messageUpdate", "messageDelete", "messageDeleteBulk"],
      discord: ["* /guilds/*/members/**", "* /channels/*/messages/**", "* /guilds/*/messages/**"],
      stores: true,
      uiTree: true,
   },
} satisfies Phoenix.Manifest;
