// @description Blocks Discord's analytics and telemetry requests
// @version 1.0.0
// @author Lil Poop

// `/science` carries the client's analytics events, `/track` the older ones
// and `/metrics` its performance counters. None of them do anything for the
// user, and Phoenix carries on when they fail.
const TELEMETRY = ["/science", "/track", "/metrics"];

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
