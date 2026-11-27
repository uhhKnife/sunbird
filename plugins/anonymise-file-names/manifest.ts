export default {
   description: "Randomizes filenames of new Discord cloud attachments while keeping their extensions and spoiler status",
   version: "1.0.0",
   author: "sh-ayu",
   permissions: {
      discord: [
         "POST /channels/*/attachments",
         "POST /channels/*/messages",
         "PATCH /channels/*/messages/*",
      ],
   },
} satisfies Phoenix.Manifest;
