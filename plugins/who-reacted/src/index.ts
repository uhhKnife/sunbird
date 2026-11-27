const snowflake = /^\d{1,20}$/;
const pageSize = 50;

function choices(reactions: Phoenix.Reaction[]) {
  return reactions.flatMap(({ emoji, count, count_details }) => {
    if (!emoji?.name || (emoji.id && !snowflake.test(emoji.id))) return [];
    const label = emoji.id ? `:${emoji.name}:` : emoji.name;
    const key = encodeURIComponent(emoji.id ? `${emoji.name}:${emoji.id}` : emoji.name);
    const normal = count_details?.normal ?? count;
    const superCount = count_details?.burst ?? 0;
    return [
      ...(normal > 0 ? [{ key, type: 0, label: `${label} · ${normal}` }] : []),
      ...(superCount > 0 ? [{ key, type: 1, label: `${label} · ${superCount} super` }] : []),
    ];
  });
}

function displayName(user: Phoenix.User): string {
  const tag = user.discriminator && user.discriminator !== "0"
    ? `${user.username}#${user.discriminator}`
    : `@${user.username}`;
  const name = user.global_name?.replace(/[\r\n]+/g, " ").trim();
  return name && name !== user.username ? `${name} (${tag})` : tag;
}

async function showReactions(ctx: Phoenix.MessageContext) {
  const channelId = ctx.message?.channel_id ?? ctx.channelId;
  if (!channelId || !snowflake.test(channelId) || !snowflake.test(ctx.messageId)) return;
  const path = `/channels/${channelId}/messages/${ctx.messageId}`;

  let message = ctx.message;
  if (!message) {
    const response = await phoenix.discord.get(path);
    if (!response.ok) {
      phoenix.ui.toast(`Could not load message (${response.status})`);
      return;
    }
    message = response.json<Phoenix.Message>();
  }

  const options = choices(message.reactions ?? []);
  if (!options.length) {
    phoenix.ui.toast("No reactions to show");
    return;
  }
  const index = options.length === 1 ? 0 : await phoenix.ui.choose({
    title: "Who reacted?",
    options: options.map(({ label }) => label),
  });
  const reaction = options[index];
  if (!reaction) return;

  let after = "";
  while (true) {
    const query = `limit=${pageSize}&type=${reaction.type}${after ? `&after=${after}` : ""}`;
    const response = await phoenix.discord.get(`${path}/reactions/${reaction.key}?${query}`);
    if (!response.ok) {
      phoenix.ui.toast(`Could not load reactions (${response.status})`);
      return;
    }

    const users = response.json<Phoenix.User[]>();
    const next = users[users.length - 1]?.id;
    const hasMore = users.length === pageSize && next !== after && snowflake.test(next ?? "");
    const selection = await phoenix.ui.showSheet({
      title: reaction.label,
      text: users.map(displayName).join("\n") || "No users on this page",
      options: hasMore ? ["Next page"] : [],
    });
    if (!hasMore || selection !== 0) return;
    after = next;
  }
}

phoenix.ui.addMessageAction({
  label: "Who reacted?",
  icon: "res://ic_mana_emoji_smiling_face_with_smiling_eyes",
  visible: (ctx) => !ctx.message || choices(ctx.message.reactions ?? []).length > 0,
  onPress(ctx) {
    void showReactions(ctx).catch(() => phoenix.ui.toast("Could not load reactions"));
  },
});
