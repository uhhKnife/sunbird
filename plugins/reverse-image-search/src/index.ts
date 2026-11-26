// @description Searches the web for an image in a message, from the message menu
// @version 1.1.0
// @author Lil Poop

const ENGINES = [
  { label: "Google Lens", url: "https://lens.google.com/uploadbyurl?url=" },
  { label: "Yandex", url: "https://yandex.com/images/search?rpt=imageview&url=" },
  { label: "Bing", url: "https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:" },
  { label: "TinEye", url: "https://www.tineye.com/search?url=" },
  { label: "SauceNAO", url: "https://saucenao.com/search.php?url=" },
  { label: "IQDB", url: "https://iqdb.org/?url=" },
];

type Image = { label: string; url: string };

const IMAGE_EXT = /\.(png|jpe?g|webp|gif|bmp|avif)(?:[?#]|$)/i;

const images = (message: Phoenix.Message | undefined): Image[] => {
  const found: Image[] = [];
  for (const file of message?.attachments ?? []) {
    if (file.content_type?.startsWith("image/") || IMAGE_EXT.test(file.filename)) {
      found.push({ label: file.filename, url: file.url });
    }
  }
  for (const embed of message?.embeds ?? []) {
    const media = embed.image ?? embed.thumbnail;
    if (media?.url) found.push({ label: embed.title || media.url.split("/").pop() || "Embed image", url: media.url });
  }
  return found;
};

const open = (url: string) => {
  if (phoenix.ui.openUrl) {
    phoenix.ui.openUrl(url);
  } else {
    phoenix.ui.copy(url);
    phoenix.ui.toast("Search link copied");
  }
};

// Which image, when a message has several.
const pick = async (list: Image[]) => {
  if (list.length < 2) return list[0];
  const picked = await phoenix.ui.choose({ title: "Which image?", options: list.map((item) => item.label) });
  return picked < 0 ? undefined : list[picked];
};

phoenix.ui.addMessageAction({
  label: "Reverse image search",
  icon: "M15.5 14h-.79l-.28-.27A6.47 6.47 0 0 0 16 9.5 6.5 6.5 0 1 0 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5Zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14Z",
  visible: (ctx) => images(ctx.message).length > 0,
  // Phones have no submenus yet, so there the engine is a dialog.
  async onPress(ctx) {
    const image = await pick(images(ctx.message));
    const engine = image ? await phoenix.ui.choose({ title: "Search with", options: ENGINES.map((item) => item.label) }) : -1;
    if (image && engine >= 0) open(ENGINES[engine].url + encodeURIComponent(image.url));
  },
  children: ENGINES.map((engine) => ({
    label: engine.label,
    async onPress(ctx: Phoenix.MessageContext) {
      const image = await pick(images(ctx.message));
      if (image) open(engine.url + encodeURIComponent(image.url));
    },
  })),
});
