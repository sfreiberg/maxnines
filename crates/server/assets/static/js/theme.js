// Applies the theme chosen in this browser. This file loads before the page is drawn,
// so a page never flashes in the wrong colours. Without scripts the page stays Carbon.
(() => {
  const STORAGE_KEY = "maxnines-theme";
  const DEFAULT_CHOICE = "carbon";
  const prefersLight = window.matchMedia("(prefers-color-scheme: light)");

  // Storage can be blocked, and then the choice just lasts until the page changes.
  function saved() {
    try {
      return localStorage.getItem(STORAGE_KEY);
    } catch {
      return null;
    }
  }

  function save(choice) {
    try {
      localStorage.setItem(STORAGE_KEY, choice);
    } catch {
      // Nothing to do. The theme still applies to this page.
    }
  }

  let choice = saved() ?? DEFAULT_CHOICE;

  function apply() {
    const system = prefersLight.matches ? "paper" : "carbon";
    document.documentElement.dataset.theme = choice === "system" ? system : choice;
    // Colours the bar around the page when it's installed as an app.
    document.querySelector('meta[name="theme-color"]').content = getComputedStyle(
      document.documentElement,
    ).getPropertyValue("--background");
    document.querySelectorAll("[data-choice]").forEach((button) => {
      button.setAttribute("aria-pressed", String(button.dataset.choice === choice));
    });
  }

  apply();
  prefersLight.addEventListener("change", apply);

  // Keeps other open tabs in step.
  window.addEventListener("storage", (event) => {
    if (event.key === STORAGE_KEY) {
      choice = event.newValue ?? DEFAULT_CHOICE;
      apply();
    }
  });

  document.addEventListener("DOMContentLoaded", () => {
    const menu = document.getElementById("theme-menu");
    menu.hidden = false;
    apply();

    menu.addEventListener("click", (event) => {
      const button = event.target.closest("[data-choice]");
      if (!button) return;
      choice = button.dataset.choice;
      save(choice);
      apply();
      menu.open = false;
    });

    document.addEventListener("click", (event) => {
      if (!menu.contains(event.target)) menu.open = false;
    });

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && menu.open) {
        menu.open = false;
        menu.querySelector("summary").focus();
      }
    });
  });
})();
