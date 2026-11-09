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
  status.textContent = updated ? "Live" : "Not updating";
});

// Leaves what someone is typing alone when the page's data updates, and the drawn map,
// which map.js redraws from the new data itself.
Idiomorph.defaults.callbacks.beforeNodeMorphed = (node) => node.id !== "host-filter" && node.id !== "map-canvas";

// Leaves anything someone has opened on the page open when its data updates.
Idiomorph.defaults.callbacks.beforeAttributeUpdated = (name, element) =>
  !(name === "open" && element.tagName === "DETAILS");

// Copy buttons beside text meant for pasting elsewhere, such as an app manifest.
// They stay hidden without scripts. Browsers only allow the clipboard API over
// HTTPS or on localhost, so plain http falls back to selecting the text and copying
// that, and if even that's refused, the text is left selected to copy by hand.
function selectText(element) {
  const range = document.createRange();
  range.selectNodeContents(element);
  const selection = window.getSelection();
  selection.removeAllRanges();
  selection.addRange(range);
}

async function copyText(element) {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(element.textContent);
      return true;
    } catch {
      // Falls back to selecting it below.
    }
  }
  selectText(element);
  try {
    return document.execCommand("copy");
  } catch {
    return false;
  }
}

for (const button of document.querySelectorAll("button[data-copy]")) button.hidden = false;

document.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-copy]");
  const source = button && document.getElementById(button.dataset.copy);
  if (!source) return;
  const copied = await copyText(source);
  const shortcut = /Mac|iPhone|iPad/.test(navigator.userAgent) ? "⌘C" : "Ctrl+C";
  button.textContent = copied ? "Copied" : `Press ${shortcut}`;
  clearTimeout(button.resetLabel);
  button.resetLabel = setTimeout(() => {
    button.textContent = "Copy";
  }, 2000);
});
