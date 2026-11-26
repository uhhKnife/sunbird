// @description Unlocks Nitro stream quality and client themes, sends custom and animated emojis and stickers as links, and renders fake emojis, stickers, and GIFs as real ones
// @version 0.6.0
// @author mantikafasi

const { gateway } = phoenix;

const settings = phoenix.settings.define({
  enableStreamQualityBypass: {
    type: "switch",
    title: "Unlock Nitro stream quality",
    description: "Allow streaming in 1080p, 1440p, Source, and 60 FPS without Nitro (Desktop)",
    default: true,
    onChange: () => syncStreamUnlock(),
  },
  enableEmojiBypass: {
    type: "switch",
    title: "Bypass emoji restrictions",
    description: "Send external and animated emojis as links when you don't have Nitro",
    default: true,
    onChange: () => syncEmojiPick(),
  },
  emojiSize: {
    type: "select",
    title: "Emoji size",
    options: [
      { value: "48" },
      { value: "32" },
      { value: "64" },
      { value: "96" },
      { value: "128" },
      { value: "160" },
    ],
  },
  useHyperLinks: {
    type: "switch",
    title: "Hide links behind the name",
    description: "Send [name](link) instead of the bare link",
    default: true,
  },
  hyperLinkText: {
    type: "text",
    title: "Link text",
    description: "{{NAME}} is replaced with the emoji or sticker name",
    default: "{{NAME}}",
  },
  renderFakeEmojis: {
    type: "switch",
    title: "Render fake emojis",
    description: "Display fake Nitro emoji links as real custom emojis",
    default: true,
  },
  renderFakeStickers: {
    type: "switch",
    title: "Render fake stickers",
    description: "Display fake Nitro sticker links as real stickers",
    default: true,
  },
  renderFakeGifs: {
    type: "switch",
    title: "Render fake GIFs",
    description: "Display hyperlinked GIFs as clean native GIF embeds",
    default: true,
  },
  renderOwnMessages: {
    type: "switch",
    title: "Include your own messages",
    description: "Also render fake emojis, stickers, and GIFs in your own messages",
    default: false,
  },
  forceFake: {
    type: "switch",
    title: "Always spoof emojis and stickers",
    description: "Send external and animated emojis and stickers as links even when you have Nitro (useful when external emojis are blocked)",
    default: false,
  },
  sendStickers: {
    type: "switch",
    title: "Send stickers as links",
    description: "Lets you pick stickers that need Nitro and sends them as links. Desktop only for now",
    default: true,
    onChange: () => applyStickers(),
  },
  stickerSize: {
    type: "select",
    title: "Sticker size",
    options: [{ value: "160" }, { value: "128" }, { value: "96" }, { value: "64" }, { value: "320" }],
  },
  unlockThemes: {
    type: "switch",
    title: "Unlock client themes",
    description:
      "Pick Nitro color themes, kept on this device only. The app then shows other Nitro features as unlocked too, but only themes work",
    default: true,
    onChange: () => applyTier(),
  },
});

interface Emoji {
  id: string;
  name: string;
  animated: boolean;
  available: boolean;
  guild: string;
}

interface CachedSticker {
  id: string;
  name: string;
  format_type: number;
  available: boolean;
  /// The sticker's server, unset for Discord's own stickers.
  guild?: string;
}

const emojis = new Map<string, Emoji>();
const byName = new Map<string, Emoji[]>();
const stickers = new Map<string, CachedSticker>();
const channelGuild = new Map<string, string>();
// The emoji last picked for each name, which `:name:` in the message box means.
const picked = new Map<string, Emoji>();
// The emoji and sticker ids of messages we rewrote, so delayed embed-only
// MESSAGE_UPDATE frames drop their fake embeds too.
const transformed = new Map<string, Set<string>>();
const TRANSFORMED_LIMIT = 2048;
// The real tier and user id, before any spoofing, from the app's cache. Null until
// the account has synced there once.
let premiumType: number | null = null;
let currentUserId: string | null = null;

const addEmojis = (guild: string, list: Phoenix.Emoji[] | undefined) => {
  for (const e of list ?? []) {
    if (!e.id || !e.name || emojis.has(e.id)) continue;
    const emoji = { id: e.id, name: e.name, animated: !!e.animated, available: e.available !== false, guild };
    emojis.set(e.id, emoji);
    byName.set(e.name, [...(byName.get(e.name) ?? []), emoji]);
  }
};

const addStickers = (list: Phoenix.Sticker[] | undefined, guild?: string) => {
  for (const s of list ?? []) {
    if (!s.id || !s.name) continue;
    stickers.set(s.id, {
      id: s.id,
      name: s.name,
      format_type: s.format_type,
      available: s.available !== false,
      guild: s.guild_id ?? guild,
    });
  }
};

// Phoenix loads guilds lazily and never hands READY to plugins: guilds and their
// emojis/stickers live in its cache. Ids in keys are zero-padded to 20 digits.
const unpad = (id: string) => id.replace(/^0+/, "");
// Desktop writes servers to its cache for minutes after READY_SUPPLEMENTAL
// (26 of 100 at first on build 2233), so reads repeat for the 5 minutes after
// it, and after that while each read finds more servers.
const SETTLE_MS = 300_000;
let settleBy = Date.now() + SETTLE_MS;
let loadedGuilds = -1;
let loadedAt = 0;
let growing = true;
const load = async () => {
  const guilds = await phoenix.stores.sql<{ g: string; e: string | null; s: string | null }>(
    "SELECT k AS g, json_extract(CAST(v AS TEXT), '$.emojis') AS e," +
      " json_extract(CAST(v AS TEXT), '$.stickers') AS s FROM guilds",
  );
  growing = guilds.length > loadedGuilds;
  loadedGuilds = guilds.length;
  for (const { g, e, s } of guilds) {
    if (e) addEmojis(unpad(g), JSON.parse(e));
    if (s) addStickers(JSON.parse(s), unpad(g));
  }
  // `guild:channel` keys: Android keeps them in `channel_stubs`, Desktop in
  // `channels`. One row per guild keeps this under the 10000-row limit.
  for (const table of ["channel_stubs", "channels"]) {
    const channels = await phoenix.stores
      .sql<{ g: string; c: string }>(
        `SELECT substr(k, 1, 20) AS g, group_concat(substr(k, 22)) AS c FROM ${table}` +
          " WHERE k NOT LIKE '00000000000000000000:%' GROUP BY 1",
      )
      .catch(() => []);
    for (const { g, c } of channels) for (const id of c.split(",")) channelGuild.set(unpad(id), unpad(g));
  }
  if (growing) phoenix.log.info(
    `${emojis.size} emojis, ${stickers.size} stickers in ${guilds.length} servers, ${channelGuild.size} channels`,
  );
};
const reload = () => {
  loadedAt = Date.now();
  return load().catch((err) => phoenix.log.warn(`reading the cache: ${err}`));
};
const refresh = () => {
  const now = Date.now();
  if ((growing || now < settleBy) && now - loadedAt > 15_000) reload();
};
reload();

if (gateway.guildCreate) {
  phoenix.on(gateway.guildCreate, (guild) => {
    addEmojis(guild.id, guild.emojis);
    addStickers((guild as Phoenix.GatewayGuild & { stickers?: Phoenix.Sticker[] }).stickers, guild.id);
    for (const channel of guild.channels ?? []) channelGuild.set(channel.id, guild.id);
  });
}
if (gateway.guildEmojisUpdate) {
  phoenix.on(gateway.guildEmojisUpdate, (update) => addEmojis(update.guild_id, update.emojis));
}
if (gateway.guildStickersUpdate) {
  phoenix.on(gateway.guildStickersUpdate, (update) => {
    const payload = update as { guild_id?: string; stickers?: Phoenix.Sticker[] };
    addStickers(payload.stickers, payload.guild_id);
  });
}

// Client themes need Nitro in the app, so while they are unlocked the app's
// copy of the account says Nitro and the cache stops telling the real tier.
// It comes from the API instead, and from real USER_UPDATEs.
const readRealTier = () =>
  phoenix.discord
    .get("/users/@me")
    .then((res) => {
      if (!res.ok) return;
      premiumType = res.json<Phoenix.CurrentUser>().premium_type ?? 0;
      applyTier();
    })
    .catch(() => {});

const readTier = () =>
  phoenix.discord
    .me()
    .then((user) => {
      if (!user) return;
      // Desktop switches accounts without reloading plugins.
      if (currentUserId !== null && currentUserId !== user.id) {
        for (const map of [emojis, byName, stickers, channelGuild, picked] as Map<string, unknown>[]) map.clear();
        loadedGuilds = -1;
        settleBy = Date.now() + SETTLE_MS;
        premiumType = null;
        reload();
      }
      currentUserId = user.id;
      if (premiumType === null) {
        if (user.premium_type !== TIER_2) premiumType = user.premium_type ?? 0;
        readRealTier();
      }
    })
    .catch((err) => phoenix.log.warn(`reading the account: ${err}`));
readTier();
// A first login fills the cache by now, and a reconnect's READY reset the tier.
if (gateway.readySupplemental) {
  phoenix.on(gateway.readySupplemental, () => {
    settleBy = Date.now() + SETTLE_MS;
    readTier();
    readRealTier();
    reload();
  });
}

// --- Client themes ---

const TIER_2 = 2;
const themesUnlocked = () => settings.unlockThemes && premiumType !== null && premiumType < TIER_2;

// Tells the app the account has Nitro, or its real tier back. Only the app's
// copy of the account changes: enqueued events skip plugins and never reach Discord.
// The cache lags the queue, so a reload's restore would win over a check of it.
const applyTier = () => {
  if (premiumType === null || premiumType >= TIER_2) return;
  const shown = themesUnlocked() ? TIER_2 : premiumType;
  phoenix.discord
    .me()
    .then((user) => {
      if (user) phoenix.enqueue(gateway.userUpdate, { ...user, premium_type: shown });
    })
    .catch((err) => phoenix.log.warn(`reading the account: ${err}`));
};
phoenix.onUnload(() => {
  if (premiumType === null || premiumType >= TIER_2) return;
  const real = premiumType;
  phoenix.discord.me().then((user) => {
    if (user) phoenix.enqueue(gateway.userUpdate, { ...user, premium_type: real });
  });
});

// A real USER_UPDATE carries the real tier, and would take the unlock away.
phoenix.hook(gateway.userUpdate, {
  before(user) {
    if (user.id !== currentUserId || user.premium_type === undefined) return;
    premiumType = user.premium_type;
    if (themesUnlocked()) user.premium_type = TIER_2;
  },
});

// Protobuf, enough to find and replace length-delimited fields of the settings.
type Field = { field: number; wire: number; start: number; data: number; end: number };

const varint = (bytes: Uint8Array, at: number): [number, number] => {
  let value = 0;
  let scale = 1;
  let byte: number;
  do {
    if (at >= bytes.length) throw new Error("truncated varint");
    byte = bytes[at++];
    value += (byte & 0x7f) * scale;
    scale *= 128;
  } while (byte & 0x80);
  return [value, at];
};

const putVarint = (value: number) => {
  const out: number[] = [];
  while (value > 0x7f) {
    out.push((value % 128) | 0x80);
    value = Math.floor(value / 128);
  }
  out.push(value);
  return Uint8Array.from(out);
};

const fields = (bytes: Uint8Array) => {
  const out: Field[] = [];
  let at = 0;
  while (at < bytes.length) {
    const start = at;
    const [key, next] = varint(bytes, at);
    const wire = key & 7;
    let data = next;
    if (wire === 0) at = varint(bytes, next)[1];
    else if (wire === 1) at = next + 8;
    else if (wire === 5) at = next + 4;
    else if (wire === 2) {
      const [length, body] = varint(bytes, next);
      data = body;
      at = body + length;
    } else throw new Error(`wire type ${wire}`);
    if (at > bytes.length) throw new Error("truncated field");
    out.push({ field: Math.floor(key / 8), wire, start, data, end: at });
  }
  return out;
};

const concat = (parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
};

/// The last `field` of `message` holding bytes, as protobuf merges them.
const child = (message: Uint8Array, field: number) => {
  const found = fields(message).filter((f) => f.field === field && f.wire === 2).pop();
  return found && message.subarray(found.data, found.end);
};

/// `message` with every `field` replaced by one holding `body`.
const replaced = (message: Uint8Array, field: number, body: Uint8Array) =>
  concat([
    ...fields(message)
      .filter((f) => f.field !== field)
      .map((f) => message.subarray(f.start, f.end)),
    putVarint(field * 8 + 2),
    putVarint(body.length),
    body,
  ]);

const BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const fromBase64 = (text: string) => {
  const clean = text.replace(/=+$/, "");
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let bits = 0;
  let count = 0;
  let at = 0;
  for (const char of clean) {
    const digit = BASE64.indexOf(char);
    if (digit < 0) throw new Error("bad base64");
    bits = ((bits << 6) | digit) & 0xffffff;
    count += 6;
    if (count >= 8) {
      count -= 8;
      out[at++] = (bits >> count) & 0xff;
    }
  }
  return out;
};

const toBase64 = (bytes: Uint8Array) => {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += BASE64[n >> 18] + BASE64[(n >> 12) & 63];
    out += i + 1 < bytes.length ? BASE64[(n >> 6) & 63] : "=";
    out += i + 2 < bytes.length ? BASE64[n & 63] : "=";
  }
  return out;
};

// PreloadedUserSettings: versions 1 { data_version 3 }, appearance 13 { client_theme_settings 3 }.
const VERSIONS = 1;
const DATA_VERSION = 3;
const APPEARANCE = 13;
const CLIENT_THEME = 3;
const SETTINGS_PATH = "/users/@me/settings-proto/1";
const THEMES_KEY = "themes";

const savedThemes = () => phoenix.storage.get<Record<string, string>>(THEMES_KEY) ?? {};

// The app sends the whole appearance message, so one without a theme clears it.
phoenix.discord.onRequest({ method: "PATCH", pathPrefix: SETTINGS_PATH }, (req) => {
  if (!themesUnlocked() || !currentUserId) return;
  try {
    const settings = req.json<{ settings?: string }>()?.settings;
    const appearance = settings && child(fromBase64(settings), APPEARANCE);
    if (!appearance) return;
    const theme = child(appearance, CLIENT_THEME);
    const themes = savedThemes();
    if (theme) themes[currentUserId] = toBase64(theme);
    else delete themes[currentUserId];
    phoenix.storage.set(THEMES_KEY, themes);
  } catch (err) {
    phoenix.log.warn(`reading a settings change: ${err}`);
  }
});

// Discord drops the theme of an account without Nitro and answers with the rest.
// The answer gets the theme back, and a data version one past Discord's so the
// app takes the settings Discord then pushes over the gateway, without the
// theme, as outdated.
// ponytail: a settings change on another device can still win once.
const withTheme = (settings: string, theme: string) => {
  let proto = fromBase64(settings);
  proto = replaced(proto, APPEARANCE, replaced(child(proto, APPEARANCE) ?? new Uint8Array(), CLIENT_THEME, fromBase64(theme)));
  const versions = child(proto, VERSIONS);
  if (versions) {
    const bumped = concat(
      fields(versions).map((f) =>
        f.field === DATA_VERSION && f.wire === 0
          ? concat([putVarint(DATA_VERSION * 8), putVarint(varint(versions, f.data)[0] + 1)])
          : versions.subarray(f.start, f.end),
      ),
    );
    proto = replaced(proto, VERSIONS, bumped);
  }
  return toBase64(proto);
};

// The account and its real tier, which right after launch are still on their way.
const account = async () => {
  if (currentUserId === null) await readTier();
  if (premiumType === null) await readRealTier();
  return currentUserId;
};

phoenix.discord.onResponse({ pathPrefix: SETTINGS_PATH }, async (res) => {
  if (!settings.unlockThemes || res.status !== 200) return;
  const id = await account();
  const theme = id && savedThemes()[id];
  if (!theme || !themesUnlocked()) return;
  try {
    const body = res.json<{ settings?: string }>();
    if (!body?.settings) return;
    phoenix.log.info("restored the theme in a settings reply");
    return { body: { ...body, settings: withTheme(body.settings, theme) } };
  } catch (err) {
    phoenix.log.warn(`restoring the theme: ${err}`);
  }
});

// READY brings Discord's settings and real tier at every connect, before the
// tier is read from the API.
if (gateway.ready) {
  phoenix.hook(gateway.ready, {
    before(ready) {
      const payload = ready as Phoenix.Ready & { user_settings_proto?: string };
      const real = payload.user?.premium_type ?? 0;
      if (!settings.unlockThemes || real >= TIER_2) return;
      premiumType = real;
      payload.user.premium_type = TIER_2;
      const theme = savedThemes()[payload.user.id];
      if (theme && payload.user_settings_proto) {
        try {
          payload.user_settings_proto = withTheme(payload.user_settings_proto, theme);
          phoenix.log.info("restored the theme in READY");
        } catch (err) {
          phoenix.log.warn(`restoring the theme: ${err}`);
        }
      }
    },
  });
}

// What Discord lets a non-Nitro user send: the server's own static emojis.
// With Nitro, anything (external emoji permission is not checked). While the
// tier is unknown, emojis go out untouched rather than as links for Nitro users.
const usable = (emoji: Emoji, guild: string | undefined) =>
  emoji.available &&
  ((!settings.forceFake && (premiumType ?? 1) > 0) || (!emoji.animated && emoji.guild === guild));

const link = (emoji: Emoji) => {
  const size = settings.emojiSize;
  const name = encodeURIComponent(emoji.name);
  const url = `https://cdn.discordapp.com/emojis/${emoji.id}.${emoji.animated ? "gif" : "webp"}?size=${size}&name=${name}&lossless=true`;
  if (!settings.useHyperLinks) return url;
  return `[${settings.hyperLinkText.replaceAll("{{NAME}}", emoji.name)}](${url})`;
};

// Rewrites `<a:name:id>` tokens and `:name:` shortcodes the sender can't use
// into links. A shortcode with a usable emoji stays: Phoenix turns a picked
// emoji's `:name:` into its token itself after onSend, by name, and would land
// inside a token put there. Links need whitespace around them to embed, one
// space between adjacent ones.
// ponytail: a `:name:` shared by several servers picks the first one we saw
// when none of them is usable here.
const rewrite = (text: string, guild: string | undefined) => {
  let linked = -1;
  return text.replace(/(?<!\\)<a?:(\w+):(\d+)>|(?<![\\<]):(\w+):(?!\d)/g, (match, _n, id, name, offset: number, whole: string) => {
    let emoji: Emoji | undefined;
    if (id) {
      emoji = emojis.get(id);
      if (!emoji || usable(emoji, guild)) return match;
    } else {
      const found = picked.has(name) ? [picked.get(name)!] : (byName.get(name) ?? []);
      if (found.some((e) => usable(e, guild))) return match;
      emoji = found.find((e) => e.available);
      if (!emoji) return match;
    }
    const end = offset + match.length;
    const before = offset > 0 && offset !== linked && !/\s/.test(whole[offset - 1]) ? " " : "";
    const after = end < whole.length && !/\s/.test(whole[end]) ? " " : "";
    linked = end;
    return before + link(emoji) + after;
  });
};

const guildOf = (ctx: Phoenix.UiContext) => (ctx.channelId ? channelGuild.get(ctx.channelId) : undefined);

// Phoenix answers a press on a locked emoji with a Nitro ad. Put `:name:` in
// the message box instead, like an unlocked pick, and remember which emoji it
// was, since several servers can have one by that name.
let releaseEmojiPick: Phoenix.Remover | undefined;
function syncEmojiPick() {
  if (settings.enableEmojiBypass && !releaseEmojiPick) {
    releaseEmojiPick = phoenix.messages.onEmojiPick((id, ctx) => {
      const emoji = emojis.get(id);
      if (!emoji || usable(emoji, guildOf(ctx))) return;
      picked.set(emoji.name, emoji);
      return `:${emoji.name}: `;
    });
  } else if (!settings.enableEmojiBypass && releaseEmojiPick) {
    releaseEmojiPick();
    releaseEmojiPick = undefined;
  }
}
syncEmojiPick();

// Go Live's resolutions and frame rates are a Desktop leaf the runtime unlocks.
let releaseStream: Phoenix.Remover | undefined;
function syncStreamUnlock() {
  if (settings.enableStreamQualityBypass && !releaseStream) {
    releaseStream = phoenix.stream?.unlockQuality();
  } else if (!settings.enableStreamQualityBypass && releaseStream) {
    releaseStream();
    releaseStream = undefined;
  }
}
syncStreamUnlock();

// ponytail: the tier and account are re-read for the next send, so the first
// send after an account switch still uses the last one's.
phoenix.messages.onSend((text, ctx) => {
  readTier();
  refresh();
  if (!settings.enableEmojiBypass || !text.includes(":")) return;
  const result = rewrite(text, guildOf(ctx));
  return result === text ? undefined : result;
});

// --- Stickers ---

// Sticker format types: 1 PNG, 2 APNG, 3 Lottie, 4 GIF. Lottie has no image to link.
const APNG = 2;
const LOTTIE = 3;
const GIF = 4;

// Discord's own stickers and a server's stickers inside it need no Nitro.
const stickerUsable = (sticker: CachedSticker, guild: string | undefined) =>
  (!settings.forceFake && (premiumType ?? TIER_2) >= TIER_2) || !sticker.guild || sticker.guild === guild;

const stickerLink = (sticker: CachedSticker) => {
  const ext = sticker.format_type === GIF ? "gif" : "png";
  const animated = sticker.format_type === APNG || sticker.format_type === GIF ? "&animated=true" : "";
  const url = `https://media.discordapp.net/stickers/${sticker.id}.${ext}?size=${settings.stickerSize}&name=${encodeURIComponent(sticker.name)}${animated}`;
  if (!settings.useHyperLinks) return url;
  return `[${settings.hyperLinkText.replaceAll("{{NAME}}", sticker.name)}](${url})`;
};

let releaseStickers: Phoenix.Remover | undefined;
const applyStickers = () => {
  if (settings.sendStickers && !releaseStickers) {
    releaseStickers = phoenix.messages.unlockStickers?.();
  } else if (!settings.sendStickers && releaseStickers) {
    releaseStickers();
    releaseStickers = undefined;
  }
};
applyStickers();

// The unlocked picker sends stickers as `sticker_ids`, which Discord refuses
// without Nitro, so those go out as links in the text instead.
phoenix.discord.onRequest({ method: "POST", pathPrefix: "/channels/", pathSuffix: "/messages" }, (req) => {
  if (!settings.sendStickers) return;
  const body = req.json<{ content?: string; sticker_ids?: string[] }>();
  if (!body?.sticker_ids?.length) return;
  const guild = channelGuild.get(/^\/channels\/(\d+)\//.exec(req.path)?.[1] ?? "");
  const kept: string[] = [];
  const links: string[] = [];
  for (const id of body.sticker_ids) {
    const sticker = stickers.get(id);
    if (!sticker || !sticker.available || sticker.format_type === LOTTIE || stickerUsable(sticker, guild)) kept.push(id);
    else links.push(stickerLink(sticker));
  }
  if (!links.length) return;
  const content = [body.content?.trim(), ...links].filter(Boolean).join(" ");
  const { sticker_ids: _, ...rest } = body;
  return { body: kept.length ? { ...rest, content, sticker_ids: kept } : { ...rest, content } };
});

// --- Incoming rendering: turn fake Nitro emojis, stickers, and GIFs into real ones ---

const CODE_SPLIT = /(```[\s\S]*?```|`[^`\n]+`)/g;
// `[label](url)` or a bare url (not inside `<...>`, `(...)` or `[...]`) to a CDN asset.
const cdnLinks = (path: string, exts: string) => {
  const url = `https?:\\/\\/(?:cdn\\.discordapp\\.com|media\\.discordapp\\.net)\\/${path}\\/\\d{15,22}\\.(?:${exts})(?:[?#][^\\s)<>]*)?`;
  return new RegExp(`\\[([^\\]\\n]*)\\]\\((${url})\\)|(?<![<(\\[])(${url})`, "gi");
};
const EMOJI_LINK_RE = cdnLinks("emojis", "png|jpe?g|webp|gif");
const STICKER_LINK_RE = cdnLinks("stickers", "png|webp|gif|apng|json");
// The id and extension of a CDN asset url, or of an embed's.
const ASSET_RE = /\/(emojis|stickers)\/(\d{15,22})\.(\w+)/i;
const GIF_HYPERLINK_RE = /\[([^\]\n]*)\]\((https?:\/\/[^\s)<>]+)\)/g;
const GIF_URL_RE =
  /^https?:\/\/(?:(?:www\.)?(?:tenor\.com\/view\/|giphy\.com\/gifs\/|klipy\.com\/gifs\/)|(?:media\d*|c|i)\.tenor\.com\/|(?:media\d*|i)\.giphy\.com\/|static\.klipy\.com\/|[^\s?#]+\.gif(?:[?#]|$))/i;
const INVISIBLE_LABEL_RE = /^[\s​-‏⁠⠀﻿._-]*$/;

const safeDecode = (s: string) => {
  try {
    return decodeURIComponent(s.replaceAll("+", " "));
  } catch {
    return s;
  }
};

// QuickJS has no URLSearchParams.
const parseQuery = (url: string) => {
  const out = new Map<string, string>();
  const q = url.indexOf("?");
  if (q === -1) return out;
  const hash = url.indexOf("#", q);
  for (const part of url.slice(q + 1, hash === -1 ? url.length : hash).split("&")) {
    if (!part) continue;
    const eq = part.indexOf("=");
    const key = eq === -1 ? part : part.slice(0, eq);
    out.set(safeDecode(key).toLowerCase(), eq === -1 ? "" : safeDecode(part.slice(eq + 1)));
  }
  return out;
};

const emojiName = (raw: string | undefined) => {
  const cleaned = (raw ?? "").replace(/^:+|:+$/g, "").replace(/[^a-zA-Z0-9_]/g, "");
  return cleaned.length >= 2 ? cleaned.slice(0, 32) : "";
};

const stickerName = (raw: string | undefined) =>
  (raw ?? "").replace(/[​-‏⁠⠀﻿]/g, "").trim().slice(0, 32);

// Sticker format types: 1 PNG, 2 APNG, 3 Lottie, 4 GIF.
const stickerFormat = (id: string, ext: string, params: Map<string, string>) => {
  const cached = stickers.get(id);
  if (cached) return cached.format_type;
  if (ext === "gif") return 4;
  if (ext === "json") return 3;
  if (ext === "apng" || params.get("animated")?.toLowerCase() === "true") return 2;
  return 1;
};

const rememberTransformed = (id: string, ids: Set<string>) => {
  transformed.set(id, ids);
  if (transformed.size > TRANSFORMED_LIMIT) {
    const oldest = transformed.keys().next().value;
    if (oldest !== undefined) transformed.delete(oldest);
  }
};

// Drops the image embeds Discord made for links we turned into emojis or stickers.
const stripFakeEmbeds = (embeds: Phoenix.Embed[] | undefined, ids: Set<string>) => {
  if (!embeds?.length || !ids.size) return false;
  const kept = embeds.filter(
    (embed) =>
      ![embed.url, embed.image?.url, embed.thumbnail?.url].some((url) => {
        const asset = url && ASSET_RE.exec(url);
        return !!asset && ids.has(asset[2]);
      }),
  );
  if (kept.length === embeds.length) return false;
  embeds.splice(0, embeds.length, ...kept);
  return true;
};

type TransformableMessage = {
  id?: string;
  author?: { id?: string };
  content?: string;
  embeds?: Phoenix.Embed[];
  sticker_items?: Phoenix.StickerItem[];
  referenced_message?: TransformableMessage | null;
  message_snapshots?: { message?: TransformableMessage }[];
};

const rendering = () => settings.renderFakeEmojis || settings.renderFakeStickers || settings.renderFakeGifs;

// Rewrites fake emoji and sticker links outside code into real ones, and
// unwraps hyperlinked GIFs. Returns whether the text changed.
const renderContent = (content: string, ids: Set<string>, found: Phoenix.StickerItem[]) => {
  const parts = content.split(CODE_SPLIT);
  for (let i = 0; i < parts.length; i += 2) {
    if (!parts[i].includes("http")) continue;
    if (settings.renderFakeEmojis) {
      parts[i] = parts[i].replace(EMOJI_LINK_RE, (_m, label, mdUrl, bareUrl) => {
        const url: string = mdUrl ?? bareUrl;
        const [, , id, ext] = ASSET_RE.exec(url)!;
        const params = parseQuery(url);
        const flag = params.get("animated")?.toLowerCase();
        const animated =
          ext.toLowerCase() === "gif" || flag === "true" || flag === "1" || (flag !== "false" && !!emojis.get(id)?.animated);
        ids.add(id);
        const name = emojiName(params.get("name")) || emojis.get(id)?.name || emojiName(label) || "emoji";
        return `<${animated ? "a" : ""}:${name}:${id}>`;
      });
    }
    if (settings.renderFakeStickers) {
      parts[i] = parts[i].replace(STICKER_LINK_RE, (_m, label, mdUrl, bareUrl) => {
        const url: string = mdUrl ?? bareUrl;
        const [, , id, ext] = ASSET_RE.exec(url)!;
        const params = parseQuery(url);
        ids.add(id);
        if (!found.some((s) => s.id === id)) {
          const name = stickers.get(id)?.name || stickerName(params.get("name")) || stickerName(label) || "Sticker";
          found.push({ id, name, format_type: stickerFormat(id, ext.toLowerCase(), params) });
        }
        return "";
      });
    }
  }
  let text = parts.join("");
  if (found.length) text = text.replace(/[ \t]{2,}/g, " ").trim();

  if (settings.renderFakeGifs && text.includes("](")) {
    // A message that is only a hyperlinked GIF shows as the GIF alone when the link is bare.
    const alone = /^\[[^\]\n]*\]\((https?:\/\/[^\s)<>]+)\)$/.exec(text.trim());
    if (alone && GIF_URL_RE.test(alone[1])) return alone[1];
    // Invisible-label GIF links beside text only hide the GIF's url; its embed stays.
    const gifParts = text.split(CODE_SPLIT);
    for (let i = 0; i < gifParts.length; i += 2) {
      gifParts[i] = gifParts[i].replace(GIF_HYPERLINK_RE, (match, label: string, url: string) =>
        GIF_URL_RE.test(url) && INVISIBLE_LABEL_RE.test(label) ? "" : match,
      );
    }
    const unwrapped = gifParts.join("");
    if (unwrapped !== text) text = unwrapped.replace(/[ \t]{2,}/g, " ").trim();
  }
  return text;
};

const transformSingle = (message: TransformableMessage): boolean => {
  if (!rendering()) return false;
  if (!settings.renderOwnMessages && currentUserId && message.author?.id === currentUserId) return false;

  // Embed-only MESSAGE_UPDATE frames carry no `content`; strip fake embeds we already converted.
  if (typeof message.content !== "string") {
    const prev = message.id && transformed.get(message.id);
    return !!prev && stripFakeEmbeds(message.embeds, prev);
  }
  if (!message.content.includes("http")) return false;

  const ids = new Set<string>();
  const found: Phoenix.StickerItem[] = [];
  const content = renderContent(message.content, ids, found);
  let changed = content !== message.content;
  message.content = content;

  const existing = message.sticker_items ?? [];
  const added = found.filter((s) => !existing.some((e) => e.id === s.id));
  if (added.length) {
    message.sticker_items = [...existing, ...added];
    changed = true;
  }
  if (ids.size) {
    if (message.id) rememberTransformed(message.id, ids);
    if (stripFakeEmbeds(message.embeds, ids)) changed = true;
  }
  return changed;
};

const transformMessage = (message: TransformableMessage | null | undefined): boolean => {
  if (!message || typeof message !== "object") return false;
  let changed = transformSingle(message);
  if (transformMessage(message.referenced_message)) changed = true;
  for (const snap of message.message_snapshots ?? []) {
    if (transformMessage(snap?.message)) changed = true;
  }
  return changed;
};

for (const event of [gateway.messageCreate, gateway.messageUpdate]) {
  phoenix.hook(event, {
    before(message) {
      refresh();
      transformMessage(message);
    },
  });
}

// History loads pass through here on every channel open, so pages with
// nothing to render are left unparsed.
const worthParsing = (res: Phoenix.InterceptedResponse) =>
  res.status >= 200 &&
  res.status < 300 &&
  rendering() &&
  (res.body.includes("/emojis/") || res.body.includes("/stickers/") || res.body.includes("]("));

// A single message (POST/PATCH), a message list, the pins' `{ items: [{ message }] }`,
// or search's `{ messages: [[message]] }`.
const transformResponse = (res: Phoenix.InterceptedResponse) => {
  if (!worthParsing(res)) return;
  const data = res.json<
    | TransformableMessage
    | TransformableMessage[]
    | { items?: { message?: TransformableMessage }[]; messages?: TransformableMessage[][] }
  >();
  if (!data) return;
  const list: (TransformableMessage | undefined)[] = Array.isArray(data)
    ? data
    : "items" in data || "messages" in data
      ? [...(data.items ?? []).map((entry) => entry?.message), ...(data.messages ?? []).flat()]
      : [data as TransformableMessage];
  let changed = false;
  for (const message of list) {
    if (transformMessage(message)) changed = true;
  }
  return changed ? { body: data } : undefined;
};

for (const [method, pathPrefix, pathSuffix] of [
  ["GET", "/channels/", "/messages"],
  ["POST", "/channels/", "/messages"],
  ["GET", "/channels/", "/pins"],
  ["GET", "/channels/", "/messages/search"],
  ["GET", "/guilds/", "/messages/search"],
] as const) {
  phoenix.discord.onResponse({ method, pathPrefix, pathSuffix }, transformResponse);
}
phoenix.discord.onResponse(
  { method: "PATCH", pathPrefix: "/channels/", pathIncludes: "/messages/" },
  transformResponse,
);
