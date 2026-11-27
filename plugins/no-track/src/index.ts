// `/science` carries the client's analytics events and `/metrics` its
// performance counters. Neither does anything for the user, and Phoenix
// carries on when they fail.
const TELEMETRY = ["/science", "/metrics"];

let blocked = 0;
for (const pathPrefix of TELEMETRY) {
  phoenix.discord.onRequest({ method: "POST", pathPrefix }, () => {
    blocked++;
    return false;
  });
}

phoenix.onUnload(() => {
  if (blocked) phoenix.log.info(`blocked ${blocked} telemetry requests`);
});
