export default {
   description: "Demo plugin covering settings, UI patches, and slash commands",
   version: "0.1.2",
   author: "amaanq",
   enabled: false,
   unlisted: true,
   permissions: {
      gateway: ["messageCreate"],
      messages: true,
   },
} satisfies Phoenix.Manifest;
