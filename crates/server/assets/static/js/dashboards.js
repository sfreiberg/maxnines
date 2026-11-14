// Shows what's picked as soon as it's picked, so the button is only for pages
// without this script.
(() => {
  const pickers = document.getElementById("dashboard-pickers");
  if (!pickers) return;
  pickers.querySelector("button[type=submit]")?.remove();
  pickers.addEventListener("change", () => pickers.requestSubmit());
})();

// Lays out a dashboard's widgets, and saves where they're dragged to.
(() => {
  const element = document.getElementById("dashboard-grid");
  if (!element) return;

  const COLUMNS = 12;
  const SAVE_DELAY_MS = 300;
  const layoutUrl = element.dataset.layoutUrl;

  const grid = GridStack.init(
    {
      column: COLUMNS,
      cellHeight: 80,
      margin: 6,
      staticGrid: !layoutUrl,
      draggable: { cancel: "a,button,input,select,textarea" },
      // Phones get one column, which isn't the layout, so it's never saved.
      columnOpts: { breakpoints: [{ w: 768, c: 1 }] },
    },
    element,
  );
  if (!layoutUrl) return;

  const status = document.getElementById("layout-status");
  let timer = null;

  async function save() {
    const layout = grid.save(false).map(({ id, x, y, w, h }) => ({ id: Number(id), x, y, w, h }));
    const body = new URLSearchParams({
      authenticity_token: element.dataset.token,
      layout: JSON.stringify(layout),
    });
    try {
      const response = await fetch(layoutUrl, { method: "POST", body });
      status.textContent = response.ok ? "Saved." : "Couldn't save that. Try reloading the page.";
    } catch {
      status.textContent = "Couldn't reach the server, so that wasn't saved.";
    }
  }

  grid.on("change", () => {
    if (grid.getColumn() !== COLUMNS) return;
    clearTimeout(timer);
    timer = setTimeout(save, SAVE_DELAY_MS);
  });
})();
