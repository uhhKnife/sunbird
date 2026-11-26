// @description Randomizes filenames of new Discord cloud attachments while keeping their extensions and spoiler status
// @version 1.0.0
// @author sh-ayu

const uploadPath = /^\/channels\/\d+\/attachments(?:\?|$)/;
const messagePath = /^\/channels\/\d+\/messages(?:\?|$)/;
const editPath = /^\/channels\/\d+\/messages\/\d+(?:\?|$)/;
const aliasPattern = /^(?:SPOILER_)?file-[a-z0-9]{10}(?:\.(?:tar\.)?[a-z0-9]{1,16})?$/i;

function anonymise(filename: string): string {
  const spoiler = filename.startsWith("SPOILER_") ? "SPOILER_" : "";
  const name = filename.slice(spoiler.length);
  const extension = name.match(/\.(?:tar\.)?[a-z0-9]{1,16}$/i);
  const suffix = extension?.index ? extension[0] : "";
  const random = Math.floor(Math.random() * 36 ** 10).toString(36).padStart(10, "0");
  return `${spoiler}file-${random}${suffix}`;
}

phoenix.discord.onRequest({ method: "POST", pathPrefix: "/channels/", pathSuffix: "/attachments" }, (req) => {
  if (!uploadPath.test(req.path)) return;
  const body = req.json<{ files?: { filename?: string }[] }>();
  if (!body || !Array.isArray(body.files)) return;

  let changed = false;
  for (const file of body.files) {
    if (typeof file?.filename !== "string" || !file.filename) continue;
    file.filename = anonymise(file.filename);
    changed = true;
  }
  if (changed) return { body };
});

function renameMessageAttachments(req: Phoenix.InterceptedRequest): Phoenix.RequestHookResult {
  const body = req.json<Phoenix.SendPayload>();
  if (!body || !Array.isArray(body.attachments)) return;

  let changed = false;
  for (const attachment of body.attachments) {
    if (typeof attachment?.uploaded_filename !== "string" || typeof attachment.filename !== "string") continue;

    // Discord's cloud upload key ends in the filename used to reserve the slot.
    const uploadName = attachment.uploaded_filename.split("/").pop();
    if (!uploadName || !aliasPattern.test(uploadName)) continue;
    const spoiler = attachment.filename.startsWith("SPOILER_") ? "SPOILER_" : "";
    const name = spoiler + uploadName.replace(/^SPOILER_/, "");
    if (attachment.filename === name && attachment.title === undefined) continue;
    attachment.filename = name;
    delete attachment.title;
    changed = true;
  }
  if (changed) return { body };
}

phoenix.discord.onRequest({ method: "POST", pathPrefix: "/channels/", pathSuffix: "/messages" }, (req) => {
  if (messagePath.test(req.path)) return renameMessageAttachments(req);
});
phoenix.discord.onRequest({ method: "PATCH", pathPrefix: "/channels/", pathIncludes: "/messages/" }, (req) => {
  if (editPath.test(req.path)) return renameMessageAttachments(req);
});
