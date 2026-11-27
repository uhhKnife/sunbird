const settings = phoenix.settings.define({
  always: {
    type: "switch",
    title: "Send every message silently",
    description: "Nobody gets a notification or a sound, like @silent",
    default: false,
  },
  prefix: {
    type: "text",
    title: "Silent prefix",
    description: "A message starting with this goes out silently, without the prefix. Empty turns it off",
    default: "!s ",
  },
});

const SUPPRESS_NOTIFICATIONS = 1 << 12;

// The prefix is taken off in `onSend`, before Phoenix posts the text, and the
// post that follows carries the flag.
let nextSilent = false;

phoenix.messages.onSend((text) => {
  const prefix = settings.prefix;
  if (!prefix || !text.startsWith(prefix)) return;
  const rest = text.slice(prefix.length);
  if (!rest.trim()) return;
  nextSilent = true;
  return rest;
});

phoenix.discord.onRequest({ method: "POST", pathPrefix: "/channels/", pathSuffix: "/messages" }, (req) => {
  if (!settings.always && !nextSilent) return;
  nextSilent = false;
  const body = req.json<{ flags?: number }>();
  if (!body) return;
  return { body: { ...body, flags: (body.flags ?? 0) | SUPPRESS_NOTIFICATIONS } };
});
