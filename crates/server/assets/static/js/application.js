// Shows on the profile bubble whether this browser can reach the server. Pages that
// don't update themselves still check for a new build, so every page keeps this current.
function showConnection(connected) {
  const link = document.getElementById("profile-link");
  if (!link) return;
  const name = link.getAttribute("aria-label").split(",")[0];
  const state = connected ? "connected to the server" : "can't reach the server";
  link.classList.toggle("disconnected", !connected);
  link.title = connected ? "Connected to the server" : "Can't reach the server";
  link.setAttribute("aria-label", `${name}, ${state}`);
  document.getElementById("connection-label").textContent = connected ? "Profile" : "Offline";

  // Coming back is for the next update to say, once the page's data is current again.
  const status = document.getElementById("live-status");
  if (status && !connected) {
    status.classList.add("stale");
    status.textContent = "Not updating";
  }
}

// A status of 0 means no answer came back. Any answer means the server is there.
document.addEventListener("htmx:afterRequest", (event) => {
  showConnection(event.detail.xhr.status !== 0);
});
window.addEventListener("offline", () => showConnection(false));

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
