export default {
   description: "Blocks Discord's analytics and telemetry requests",
   version: "1.0.0",
   author: "Lil Poop",
   permissions: {
      discord: ["POST /science", "POST /metrics/**"],
   },
} satisfies Phoenix.Manifest;
