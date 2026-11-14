// Suggests fact names and values while typing in the host filter. The box works as
// a plain search form without this. Suggestions come from what agents report, so
// they're only ever set as text.
(() => {
  const form = document.getElementById("host-filter");
  if (!form) return;

  const input = form.querySelector('input[name="filter"]');
  const list = document.getElementById("host-filter-options");
  const DELAY_MS = 120;

  let suggestions = [];
  let active = -1;
  let timer = null;
  let request = null;

  // Where the term under the cursor starts and ends. Spaces in quotes don't split it.
  function currentTerm() {
    const text = input.value;
    const cursor = input.selectionStart ?? text.length;
    let start = 0;
    let quoted = false;
    for (let index = 0; index < cursor; index += 1) {
      if (text[index] === '"') quoted = !quoted;
      else if (!quoted && /\s/.test(text[index])) start = index + 1;
    }
    let end = cursor;
    while (end < text.length && (quoted || !/\s/.test(text[end]))) {
      if (text[end] === '"') quoted = !quoted;
      end += 1;
    }
    return { start, end, text: text.slice(start, end) };
  }

  function close() {
    suggestions = [];
    active = -1;
    list.hidden = true;
    list.replaceChildren();
    input.setAttribute("aria-expanded", "false");
    input.removeAttribute("aria-activedescendant");
  }

  function show(found) {
    if (found.length === 0) {
      close();
      return;
    }
    suggestions = found;
    active = -1;
    list.replaceChildren(
      ...found.map((suggestion, index) => {
        const item = document.createElement("li");
        item.id = `host-filter-option-${index}`;
        item.setAttribute("role", "option");
        item.setAttribute("aria-selected", "false");
        item.textContent = suggestion.label;
        return item;
      }),
    );
    list.hidden = false;
    input.setAttribute("aria-expanded", "true");
    input.removeAttribute("aria-activedescendant");
  }

  function highlight(index) {
    active = index;
    [...list.children].forEach((item, position) => {
      const chosen = position === index;
      item.classList.toggle("active", chosen);
      item.setAttribute("aria-selected", String(chosen));
      if (chosen) {
        item.scrollIntoView({ block: "nearest" });
        input.setAttribute("aria-activedescendant", item.id);
      }
    });
  }

  async function load() {
    request?.abort();
    request = new AbortController();
    const term = currentTerm().text;
    try {
      const response = await fetch(`/hosts/filter-options?term=${encodeURIComponent(term)}`, {
        signal: request.signal,
      });
      if (response.ok && document.activeElement === input) show(await response.json());
    } catch (error) {
      if (error.name !== "AbortError") close();
    }
  }

  function loadSoon() {
    clearTimeout(timer);
    timer = setTimeout(load, DELAY_MS);
  }

  function choose(index) {
    const term = currentTerm();
    const { text } = suggestions[index];
    const needsValue = text.endsWith("=");
    const before = input.value.slice(0, term.start);
    const after = input.value.slice(term.end);
    const finished = before + text + (needsValue || after.startsWith(" ") ? "" : " ");
    input.value = finished + after;
    input.setSelectionRange(finished.length, finished.length);
    close();
    if (needsValue) load();
  }

  input.addEventListener("input", loadSoon);
  input.addEventListener("focus", loadSoon);
  input.addEventListener("click", loadSoon);
  input.addEventListener("blur", () => {
    clearTimeout(timer);
    request?.abort();
    close();
  });

  input.addEventListener("keydown", (event) => {
    const open = suggestions.length > 0;
    if (event.key === "ArrowDown" && open) {
      event.preventDefault();
      highlight((active + 1) % suggestions.length);
    } else if (event.key === "ArrowUp" && open) {
      event.preventDefault();
      highlight((active - 1 + suggestions.length) % suggestions.length);
    } else if (event.key === "Escape" && open) {
      event.preventDefault();
      close();
    } else if (event.key === "Enter" && active >= 0) {
      event.preventDefault();
      choose(active);
    } else if (event.key === "Tab" && open) {
      event.preventDefault();
      choose(active >= 0 ? active : 0);
    }
  });

  // On press rather than click, as pressing takes the focus out of the box.
  list.addEventListener("mousedown", (event) => {
    event.preventDefault();
    const item = event.target.closest("li");
    if (item) choose([...list.children].indexOf(item));
  });
})();
