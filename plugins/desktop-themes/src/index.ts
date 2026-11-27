// bg tertiary, secondary, primary, elevated, accent, text, muted text, border.
const PRESETS: Record<string, string[]> = {
  Midnight: ["#0b0d14", "#0f121c", "#141825", "#191e2e", "#7289da", "#eef1fa", "#9ba5c0", "#252c42"],
  "Catppuccin Mocha": ["#11111b", "#181825", "#1e1e2e", "#313244", "#cba6f7", "#cdd6f4", "#a6adc8", "#45475a"],
  "Catppuccin Latte": ["#dce0e8", "#e6e9ef", "#eff1f5", "#ccd0da", "#8839ef", "#4c4f69", "#6c6f85", "#bcc0cc"],
};

const presetCss = (colors: string[]) => {
  const vars = [
    "bg-tertiary", "bg-secondary", "bg-primary", "bg-elevated",
    "accent-color", "text-normal", "text-muted", "ui-border-color",
  ];
  return `:root { ${vars.map((v, i) => `--${v}: ${colors[i]};`).join(" ")} }`;
};

const themes = phoenix.themes;

if (!themes?.supported()) {
  phoenix.log.info("desktop-themes: this Discord build can't be themed");
} else {
  const apply = (theme: string) => {
    try {
      if (theme.startsWith("file:")) themes.apply(theme.slice(5));
      else if (PRESETS[theme]) themes.setCss(presetCss(PRESETS[theme]));
      else themes.clear();
    } catch (err) {
      phoenix.log.warn(`desktop-themes: ${err}`);
      themes.clear();
    }
  };

  const settings = phoenix.settings.define({
    theme: {
      type: "select",
      title: "Theme",
      description: "A preset, or a .theme.css file from the themes folder (reload plugins after adding one)",
      options: [
        { value: "off", label: "Off" },
        ...Object.keys(PRESETS).map((name) => ({ value: name, label: name })),
        ...themes.list().map((t) => ({ value: `file:${t.id}`, label: t.name })),
      ],
      default: "off",
      onChange: (value) => apply(value),
    },
    openThemesDir: {
      type: "button",
      title: "Open themes folder",
      onPress: () => themes.openThemesDir(),
    },
  });

  apply(settings.theme);
}
