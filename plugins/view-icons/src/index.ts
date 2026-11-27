const CDN = "https://cdn.discordapp.com";
const SIZE = 4096;

// Pomelo usernames pick the default avatar from the id, older ones from the
// discriminator.
const defaultAvatar = (user: Phoenix.User) => {
  const index =
    user.discriminator && user.discriminator !== "0"
      ? Number(user.discriminator) % 5
      : Number((BigInt(user.id) >> 22n) % 6n);
  return `${CDN}/embed/avatars/${index}.png`;
};

const avatar = (user: Phoenix.User) => {
  if (!user.avatar) return defaultAvatar(user);
  const ext = user.avatar.startsWith("a_") ? "gif" : "png";
  return `${CDN}/avatars/${user.id}/${user.avatar}.${ext}?size=${SIZE}`;
};

const open = (url: string) => {
  if (phoenix.ui.openUrl) {
    phoenix.ui.openUrl(url);
  } else {
    phoenix.ui.copy(url);
    phoenix.ui.toast("Avatar link copied");
  }
};

phoenix.ui.addMessageAction({
  label: "View avatar",
  icon: "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2Zm0 4c1.93 0 3.5 1.57 3.5 3.5S13.93 13 12 13s-3.5-1.57-3.5-3.5S10.07 6 12 6Zm0 14c-2.03 0-4.43-.82-6.14-2.88a9.95 9.95 0 0 1 12.28 0C16.43 19.18 14.03 20 12 20Z",
  visible: (ctx) => !!ctx.message?.author?.id,
  onPress(ctx) {
    const author = ctx.message?.author;
    if (author) open(avatar(author));
  },
});
