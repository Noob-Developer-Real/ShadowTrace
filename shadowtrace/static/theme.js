(() => {
  try {
    const theme = localStorage.getItem("shadowtrace-theme");
    if (["light", "dark", "system"].includes(theme)) document.documentElement.dataset.theme = theme;
  } catch { /* Light mode is available when browser storage is disabled. */ }
})();
