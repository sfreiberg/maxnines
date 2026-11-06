// Warns when a page has stopped updating, so old data isn't mistaken for current data.
document.addEventListener("htmx:afterRequest", (event) => {
  if (event.detail.elt.id !== "page") return;
  const updated = event.detail.successful === true;
  document.getElementById("stale-notice").hidden = updated;

  const status = document.getElementById("live-status");
  status.classList.toggle("stale", !updated);
  status.textContent = updated
    ? `Live · ${new Date().toISOString().slice(11, 19)} UTC`
    : "Not updating";
});

// Leaves what someone is typing alone when the page's data updates.
Idiomorph.defaults.callbacks.beforeNodeMorphed = (node) => node.id !== "host-filter";

// Leaves anything someone has opened on the page open when its data updates.
Idiomorph.defaults.callbacks.beforeAttributeUpdated = (name, element) =>
  !(name === "open" && element.tagName === "DETAILS");
