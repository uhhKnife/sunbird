export interface Role {
  id: string;
  name: string;
  position: number;
  permissions: string;
}

export interface Overwrite {
  id: string;
  type: number;
  allow: string;
  deny: string;
}

export interface Member {
  roles?: string[];
  nick?: string | null;
  communication_disabled_until?: string | null;
}

export interface Guild {
  roles?: Role[] | Record<string, Role>;
  owner_id?: string;
  properties?: { owner_id?: string };
}

export interface Channel {
  name?: string;
  type?: number;
  parent_id?: string | null;
}

// In the order Discord's role settings list them. Retired bits like Use Clyde AI are left out.
export const GROUPS: [string, [number, string][]][] = [
  ["General", [
    [10, "View Channels"], [4, "Manage Channels"], [28, "Manage Roles"], [43, "Create Expressions"],
    [30, "Manage Expressions"], [7, "View Audit Log"], [19, "View Server Insights"],
    [41, "View Server Subscription Insights"], [29, "Manage Webhooks"], [5, "Manage Server"],
    [0, "Create Invite"], [26, "Change Nickname"], [27, "Manage Nicknames"], [1, "Kick Members"],
    [2, "Ban Members"], [40, "Timeout Members"], [44, "Create Events"], [33, "Manage Events"],
    [3, "Administrator"],
  ]],
  ["Text", [
    [11, "Send Messages"], [38, "Send Messages in Threads"], [35, "Create Public Threads"],
    [36, "Create Private Threads"], [14, "Embed Links"], [15, "Attach Files"], [6, "Add Reactions"],
    [18, "Use External Emoji"], [37, "Use External Stickers"],
    [17, "Mention @everyone, @here, and All Roles"], [13, "Manage Messages"], [51, "Pin Messages"],
    [52, "Bypass Slowmode"], [34, "Manage Threads"], [16, "Read Message History"],
    [12, "Send Text-to-Speech Messages"], [46, "Send Voice Messages"], [49, "Create Polls"],
    [31, "Use Application Commands"], [50, "Use External Apps"],
  ]],
  ["Voice", [
    [20, "Connect"], [21, "Speak"], [9, "Video"], [39, "Use Activities"], [42, "Use Soundboard"],
    [45, "Use External Sounds"], [25, "Use Voice Activity"], [8, "Priority Speaker"],
    [22, "Mute Members"], [23, "Deafen Members"], [24, "Move Members"],
    [48, "Set Voice Channel Status"], [32, "Request to Speak"],
  ]],
];

export const NAMES = new Map(GROUPS.flatMap(([, perms]) => perms));
export const EVERYONE = "@everyone";

const ADMINISTRATOR = 3;
const VIEW_CHANNEL = 10;
const READ_MESSAGE_HISTORY = 16;
const THREADS = [10, 11, 12];

export const has = (value: bigint, bit: number) => ((value >> BigInt(bit)) & 1n) === 1n;
const flag = (bit: number) => 1n << BigInt(bit);

export const bitsOf = (value: bigint) => {
  const out: number[] = [];
  for (let bit = 0; bit < 64; bit++) if (has(value, bit)) out.push(bit);
  return out;
};

/// Bits with a name, which are all that is shown or counted.
export const known = (value: bigint) => bitsOf(value).filter((bit) => NAMES.has(bit));

const big = (value: string | undefined) => {
  try {
    return BigInt(value ?? 0);
  } catch {
    return 0n;
  }
};

export interface Granted {
  value: bigint;
  /// Where each bit came from: a role name, or the overwrite that changed it.
  source: Map<number, string>;
  /// Bits an overwrite took away, and which one.
  denied: Map<number, string>;
}

export interface Permissions {
  /// The member's roles, highest first, without @everyone.
  roles: Role[];
  /// "Server owner" or "Administrator (via role)", which grant everything everywhere.
  all?: string;
  server: Granted;
  /// Absent when the channel's overwrites are not known.
  channel?: Granted;
  timedOut: boolean;
}

export interface Input {
  guildId: string;
  userId: string;
  guild: Guild;
  member: Member;
  overwrites?: Overwrite[];
  now?: number;
}

export function compute({ guildId, userId, guild, member, overwrites, now = Date.now() }: Input): Permissions {
  const list = Array.isArray(guild.roles) ? guild.roles : Object.values(guild.roles ?? {});
  const byId = new Map(list.map((role) => [role.id, role]));
  // @everyone has the server's id and is never in a member's roles.
  const roles = [...new Set(member.roles ?? [])]
    .filter((id) => id !== guildId)
    .map((id) => byId.get(id))
    .filter((role): role is Role => !!role)
    .sort((a, b) => b.position - a.position);
  const everyone = byId.get(guildId);

  // @everyone goes first, so a bit everyone has is never credited to a role.
  const server: Granted = { value: 0n, source: new Map(), denied: new Map() };
  for (const [value, name] of [
    ...(everyone ? [[big(everyone.permissions), EVERYONE] as const] : []),
    ...roles.map((role) => [big(role.permissions), role.name] as const),
  ]) {
    for (const bit of bitsOf(value & ~server.value)) server.source.set(bit, name);
    server.value |= value;
  }

  let all: string | undefined;
  if ((guild.properties?.owner_id ?? guild.owner_id) === userId) all = "Server owner";
  else if (has(server.value, ADMINISTRATOR)) all = `Administrator (via ${server.source.get(ADMINISTRATOR)})`;
  if (all) return { roles, all, server, timedOut: false };

  const channel = overwrites && applyOverwrites(server, overwrites, guildId, userId, roles);
  const timedOut =
    !!member.communication_disabled_until && Date.parse(member.communication_disabled_until) > now;
  if (timedOut) for (const granted of [server, channel]) if (granted) timeout(granted);
  return { roles, server, channel, timedOut };
}

function applyOverwrites(
  server: Granted,
  overwrites: Overwrite[],
  guildId: string,
  userId: string,
  roles: Role[],
): Granted {
  const out: Granted = { value: server.value, source: new Map(server.source), denied: new Map() };
  // Only bits an overwrite actually changes take it as their source.
  const step = (allow: bigint, deny: bigint, label: (bit: number) => string) => {
    const before = out.value;
    const after = (before & ~deny) | allow;
    for (const bit of bitsOf(before & ~after)) {
      out.denied.set(bit, label(bit));
      out.source.delete(bit);
    }
    for (const bit of bitsOf(after & ~before)) {
      out.source.set(bit, label(bit));
      out.denied.delete(bit);
    }
    out.value = after;
  };

  const everyone = overwrites.find((o) => o.id === guildId);
  if (everyone) step(big(everyone.allow), big(everyone.deny), () => `overwrite for ${EVERYONE}`);

  // Role overwrites apply together, denies first, so any allow among them wins.
  let allow = 0n;
  let deny = 0n;
  const allowedBy = new Map<number, string>();
  const deniedBy = new Map<number, string>();
  for (const role of roles) {
    const o = overwrites.find((o) => o.type === 0 && o.id === role.id);
    if (!o) continue;
    for (const bit of bitsOf(big(o.allow))) if (!allowedBy.has(bit)) allowedBy.set(bit, role.name);
    for (const bit of bitsOf(big(o.deny))) if (!deniedBy.has(bit)) deniedBy.set(bit, role.name);
    allow |= big(o.allow);
    deny |= big(o.deny);
  }
  step(allow, deny, (bit) => `overwrite for ${allowedBy.get(bit) ?? deniedBy.get(bit)}`);

  const member = overwrites.find((o) => o.type === 1 && o.id === userId);
  if (member) step(big(member.allow), big(member.deny), () => "overwrite for this member");

  // Without View Channels nothing else counts in the channel.
  if (!has(out.value, VIEW_CHANNEL)) {
    return { value: 0n, source: new Map(), denied: new Map([[VIEW_CHANNEL, out.denied.get(VIEW_CHANNEL) ?? "not granted"]]) };
  }
  return out;
}

function timeout(granted: Granted) {
  granted.value &= flag(VIEW_CHANNEL) | flag(READ_MESSAGE_HISTORY);
  for (const bit of [...granted.source.keys()]) if (!has(granted.value, bit)) granted.source.delete(bit);
}

export type Sql = <Row = Record<string, unknown>>(query: string, ...args: unknown[]) => Promise<Row[]>;

const pad = (id: string) => id.padStart(20, "0");
const unpad = (key: string) => key.replace(/^0+/, "");

const row = async <T>(sql: Sql, table: string, key: string) => {
  const rows = await sql<{ v: string }>(`SELECT CAST(v AS TEXT) AS v FROM ${table} WHERE k = ? LIMIT 1`, key);
  return rows[0] ? (JSON.parse(rows[0].v) as T) : undefined;
};

export interface Loaded {
  guildId: string;
  channel: Channel;
  member: Member;
  permissions: Permissions;
}

/// Everything from Phoenix's cache, never the API. A string says why it can't be shown.
export async function load(sql: Sql, channelId: string, userId: string, now?: number): Promise<Loaded | string> {
  // Channels are keyed `guild:channel`, and DMs have a zero guild.
  const rows = await sql<{ k: string; v: string }>(
    "SELECT k, CAST(v AS TEXT) AS v FROM channels WHERE k LIKE ? LIMIT 1",
    `%:${pad(channelId)}`,
  );
  if (!rows[0]) return "This channel is not in Phoenix's cache.";
  const guildId = unpad(rows[0].k.split(":")[0]);
  if (!guildId) return "Permissions only exist in servers.";
  const channel = JSON.parse(rows[0].v) as Channel;

  const guild = await row<Guild>(sql, "guilds", pad(guildId));
  if (!guild) return "This server is not in Phoenix's cache.";
  const member = await row<Member>(sql, "members", `${pad(guildId)}:${pad(userId)}`);
  if (!member) return "This member is not in Phoenix's cache yet. Open the member list or their profile first.";

  // A thread takes its permissions from the channel it is in.
  const source = THREADS.includes(channel.type ?? -1) && channel.parent_id ? channel.parent_id : channelId;
  let overwrites: Overwrite[] | undefined;
  try {
    // A channel without overwrites has no row.
    overwrites = (await row<Overwrite[]>(sql, "channel_overwrites", `${pad(guildId)}:${pad(source)}`)) ?? [];
  } catch {
    // Older Phoenix builds have no channel_overwrites table, and then only the server part shows.
  }
  const permissions = compute({ guildId, userId, guild, member, overwrites, now });
  return { guildId, channel, member, permissions };
}
