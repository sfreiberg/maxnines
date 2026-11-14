// Works out Match system, which only the browser knows, and colours the bar around
// an installed app. This file loads before the page is drawn, so neither ever flashes.
(() => {
  const root = document.documentElement;
  const prefersLight = window.matchMedia("(prefers-color-scheme: light)");

  function apply() {
    if (root.dataset.choice === "system") {
      root.dataset.theme = prefersLight.matches ? "paper" : "carbon";
    }
    document.querySelector('meta[name="theme-color"]').content =
      getComputedStyle(root).getPropertyValue("--background");
  }

  apply();
  prefersLight.addEventListener("change", apply);
})();
