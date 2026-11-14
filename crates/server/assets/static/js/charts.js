// Hovering a moment on one chart shows that moment on every chart, to compare them.
// Charts work on their own without this, each showing its own moments.
(() => {
  let moment = null;

  // A chart's column for a moment, or nothing if the chart has a gap there.
  function columnAt(chart, time) {
    let closest = null;
    let distance = Number(chart.dataset.reach);
    for (const column of chart.querySelectorAll(".column")) {
      const away = Math.abs(Number(column.dataset.time) - time);
      if (away <= distance) {
        closest = column;
        distance = away;
      }
    }
    return closest;
  }

  function show() {
    for (const column of document.querySelectorAll(".chart .column.linked")) {
      column.classList.remove("linked");
    }
    if (moment === null) return;
    for (const chart of document.querySelectorAll("svg.chart")) {
      columnAt(chart, moment)?.classList.add("linked");
    }
  }

  function moveTo(time) {
    if (time === moment) return;
    moment = time;
    show();
  }

  document.addEventListener("pointerover", (event) => {
    const column = event.target.closest(".column");
    moveTo(column ? Number(column.dataset.time) : null);
  });
  document.documentElement.addEventListener("pointerleave", () => moveTo(null));

  // Updating the page's data clears what's showing.
  document.addEventListener("htmx:afterSettle", show);
})();
