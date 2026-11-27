const STORED = "collapsed";
const collapseChannels = phoenix.ui.collapseChannels;

let restore: Phoenix.Remover | null = null;
let shortcut: Phoenix.Remover | null = null;
let button: Phoenix.ButtonRemover | null = null;

const look = () =>
  restore
    ? { icon: "res://ic_mana_panel_closed", label: "Show Channel List" }
    : { icon: "res://ic_mana_panel_open", label: "Hide Channel List" };

const collapse = (on: boolean) => {
  if (!collapseChannels) return;
  if (on && !restore) {
    restore = collapseChannels();
  } else if (!on && restore) {
    restore();
    restore = null;
  }
  button?.update(look());
  phoenix.storage.set(STORED, restore !== null && settings.remember);
};

const toggle = () => collapse(!restore);

const syncButton = (on: boolean) => {
  if (!collapseChannels) return;
  if (on && !button) {
    button = phoenix.ui.addHeaderButton({ ...look(), onPress: toggle });
  } else if (!on && button) {
    button();
    button = null;
  }
};

const syncShortcut = (on: boolean) => {
  if (!collapseChannels) return;
  if (on && !shortcut && phoenix.ui.addShortcut) {
    shortcut = phoenix.ui.addShortcut({ key: "B", ctrl: true, shift: true, run: toggle });
  } else if (!on && shortcut) {
    shortcut();
    shortcut = null;
  }
};

const settings = phoenix.settings.define({
  button: {
    type: "switch",
    title: "Button in the channel header",
    description: "Next to the member list button",
    default: true,
    onChange: syncButton,
  },
  shortcut: {
    type: "switch",
    title: "Toggle with Ctrl+Shift+B",
    description: "While Discord is focused (Windows)",
    default: true,
    onChange: syncShortcut,
  },
  remember: {
    type: "switch",
    title: "Stay collapsed after a restart",
    default: true,
    onChange: (on) => {
      if (collapseChannels) phoenix.storage.set(STORED, on && restore !== null);
    },
  },
});

if (collapseChannels) {
  if (settings.remember && phoenix.storage.get<boolean>(STORED)) collapse(true);
  syncButton(settings.button);
  syncShortcut(settings.shortcut);
} else {
  phoenix.log.warn("the channel sidebar is unavailable on this build of Phoenix");
}
