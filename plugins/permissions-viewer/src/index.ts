import { EVERYONE, GROUPS, NAMES, type Granted, has, known, load } from "./permissions";

const sql = phoenix.stores.sql.bind(phoenix.stores);

const grouped = (prefix: string, granted: Granted): Phoenix.PageSection[] => {
  const sections: Phoenix.PageSection[] = [];
  for (const [group, perms] of GROUPS) {
    const lines = perms
      .filter(([bit]) => has(granted.value, bit))
      .map(([bit, name]) => {
        const source = granted.source.get(bit);
        return source && source !== EVERYONE ? `✅ ${name} (${source})` : `✅ ${name}`;
      });
    if (lines.length) sections.push({ type: "text", title: `${prefix} · ${group} (${lines.length})`, text: lines.join("\n") });
  }
  return sections.length ? sections : [{ type: "text", title: prefix, text: "No permissions" }];
};

const show = async (channelId: string, author: Phoenix.User) => {
  const found = await load(sql, channelId, author.id);
  const name = (typeof found === "object" && found.member.nick) || author.global_name || author.username;
  const title = `Permissions · ${name}`;
  if (typeof found === "string") {
    phoenix.ui.openPage({ title, sections: [{ type: "text", text: found }] });
    return;
  }
  const { channel, permissions } = found;
  const { roles, all, server } = permissions;
  const channelName = `#${channel.name ?? "channel"}`;
  const here = `In ${channelName}`;

  const sections: Phoenix.PageSection[] = [
    { type: "text", title: `Roles (${roles.length + 1})`, text: [...roles.map((r) => r.name), EVERYONE].join(" · ") },
  ];
  if (all) {
    sections.push({ type: "text", title: "Permissions", text: `${all}, has every permission` });
  } else {
    sections.push(...grouped("Server", server));
    if (permissions.channel) {
      sections.push(...grouped(here, permissions.channel));
      const denied = [...permissions.channel.denied].filter(([bit]) => NAMES.has(bit));
      if (denied.length) {
        sections.push({
          type: "text",
          title: `Denied in ${channelName} (${denied.length})`,
          text: denied.map(([bit, why]) => `❌ ${NAMES.get(bit)} (${why})`).join("\n"),
        });
      }
    }
    if (permissions.timedOut) {
      sections.push({ type: "text", text: "Timed out, so only View Channels and Read Message History apply." });
    }
  }

  const copy = sections
    .map((s) => (s.type === "text" ? [s.title, s.text].filter(Boolean).join("\n") : ""))
    .join("\n\n");
  sections.unshift({
    type: "buttons",
    buttons: [
      {
        label: "Copy",
        icon: "message.actions.copy_text",
        onPress() {
          phoenix.ui.copy(`${title}\n\n${copy}`);
          phoenix.ui.toast("Copied permissions");
        },
      },
    ],
  });
  phoenix.ui.openPage({ title, sections });
};

const cachedAuthor = async (messageId: string) => {
  const rows = await sql<{ a: string }>(
    "SELECT json_extract(CAST(v AS TEXT), '$.author') AS a FROM messages WHERE k LIKE ? LIMIT 1",
    `%:${messageId.padStart(20, "0")}`,
  );
  return rows[0]?.a ? (JSON.parse(rows[0].a) as Phoenix.User) : undefined;
};

phoenix.ui.addMessageAction({
  label: "View Permissions",
  icon: "res://ic_mana_paper_lock",
  onPress(ctx) {
    (async () => {
      const author = ctx.message?.author ?? (await cachedAuthor(ctx.messageId));
      if (!ctx.channelId || !author) {
        phoenix.ui.toast("This message is not cached");
        return;
      }
      await show(ctx.channelId, author);
    })().catch((e) => {
      phoenix.log.error("permissions-viewer:", e);
      phoenix.ui.toast("Couldn't read permissions from the cache");
    });
  },
});

phoenix.ui.addProfileSection({
  title: "Permissions",
  async render({ userId, channelId }) {
    if (!userId || !channelId) return null;
    const found = await load(sql, channelId, userId);
    if (typeof found === "string") return null;
    const { roles, all, server } = found.permissions;
    const names = roles.map((role) => role.name);
    const shown = names.slice(0, 3).join(" · ") || EVERYONE;
    const more = names.length > 3 ? ` · +${names.length - 3}` : "";
    return `${shown}${more} · ${all ?? `${known(server.value).length} permissions`}`;
  },
});
