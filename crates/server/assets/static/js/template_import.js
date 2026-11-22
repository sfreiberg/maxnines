// Puts what's in a chosen file in the box it's for, so a template can be imported
// from a file as well as pasted. The form works by pasting without this.
(() => {
  document.addEventListener("change", async (event) => {
    const input = event.target;
    if (!input.matches?.("input[type=file][data-fills]")) return;
    const box = document.getElementById(input.dataset.fills);
    const file = input.files?.[0];
    if (!box || !file) return;
    box.value = await file.text();
  });
})();
