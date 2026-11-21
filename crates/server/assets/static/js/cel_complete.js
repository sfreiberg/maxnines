// Suggests what can come next while typing CEL in a field marked data-cel: metrics
// by their names, a step at a time through the dots, the series of metrics that have
// fixed ones, facts, the names conditions know and functions. The fields work as
// plain text boxes without this. What's suggested comes from /conditions/suggestions,
// so it's the server's own catalog, and from the data-cel-local of the form, for a
// template's own metrics. Everything is set as text, never as markup.
//
// data-cel says where the field is: "condition" for an alert's conditions,
// "applies_to" for which hosts, "when" for what a template's discovery found, and
// "value" for working a template's metric out.
(() => {
  const MAX_SHOWN = 12;
  let catalog = null;
  let loading = null;
  let field = null;
  let list = null;
  let found = [];
  let active = -1;
  let numbered = 0;

  function load() {
    loading ??= fetch("/conditions/suggestions", { headers: { Accept: "application/json" } })
      .then((response) => (response.ok ? response.json() : null))
      .then((loaded) => {
        catalog = loaded;
        return loaded;
      })
      .catch(() => {
        loading = null;
        return null;
      });
    return loading;
  }

  // A template's own metrics and what its discovery finds, from the form, if any.
  function localOf(input) {
    const holder = input.closest("[data-cel-local]");
    if (!holder) return null;
    try {
      return JSON.parse(holder.dataset.celLocal);
    } catch {
      return null;
    }
  }

  // An alert rule with a calculation is about its value instead.
  function scopeOf(input) {
    const scope = input.dataset.cel;
    const calculation = input.form?.elements.namedItem("calculation");
    if (scope === "condition" && calculation && calculation.value) return "calculation";
    return scope;
  }

  // What's being typed before the cursor: a series in brackets, or a name with any
  // dots in it. Nothing inside other text in quotes.
  function typedAt(input) {
    const before = input.value.slice(0, input.selectionStart ?? input.value.length);
    const series = before.match(/([A-Za-z_][\w.]*)\[\s*(['"])([^'"]*)$/);
    if (series) {
      return { kind: "series", metric: series[1], quote: series[2], text: series[3], start: before.length - series[3].length };
    }
    const quotes = (before.match(/['"]/g) || []).length;
    if (quotes % 2 === 1) return null;
    const name = before.match(/[A-Za-z_][\w]*(?:\.[\w]*)*$/);
    if (!name) return null;
    if (before.length > name[0].length && /[\w.]/.test(before[before.length - name[0].length - 1])) return null;
    return { kind: "name", text: name[0], start: before.length - name[0].length };
  }

  function usable(suggestion, scope) {
    const where = scope === "calculation" ? ["calculation", "condition"] : [scope];
    return suggestion.used_in.some((place) => where.includes(place));
  }

  // Everything that could go here, each as what's shown, what's put in and a word
  // about it.
  function candidates(input, typed) {
    const scope = scopeOf(input);
    const local = localOf(input);
    const all = [];
    const add = (label, about, insert = label) => all.push({ label, about, insert });

    if (typed.kind === "series") {
      const metric = catalog.metrics.find((each) => each.name === typed.metric);
      for (const series of metric?.series ?? []) add(series, metric.title, `${series}${typed.quote}]`);
      return all.filter((each) => each.label.startsWith(typed.text));
    }

    const metricsHere = scope === "condition" || scope === "value";
    if (local && metricsHere) {
      for (const metric of local.metrics ?? []) {
        const labels = metric.labels.length ? `, by ${metric.labels.join(", ")}` : "";
        add(metric.name, `${metric.kind}${labels}`);
        add(`${local.prefix}.${metric.name}`, `${metric.kind}${labels}`);
      }
    }
    if (local && scope === "when") {
      for (const name of local.discovered ?? []) add(name, "found by discovery");
    }
    if (scope === "condition") {
      for (const metric of catalog.metrics) add(metric.name, metric.title);
    }
    for (const variable of catalog.variables) {
      if (usable(variable, scope)) add(variable.insert, variable.about);
    }
    if (typed.text.startsWith("facts.")) {
      for (const fact of catalog.facts) add(`facts.${fact}`, "fact");
    }
    for (const call of catalog.functions) {
      if (usable(call, scope)) add(call.name, call.about, call.insert);
    }
    // A method on whatever comes before the last dot, when that isn't a name to go on with.
    const dot = typed.text.lastIndexOf(".");
    if (dot > 0) {
      const base = typed.text.slice(0, dot + 1);
      const goesOn = all.some((each) => each.label.startsWith(base));
      if (!goesOn) {
        for (const method of catalog.methods) add(base + method.name, method.about, base + method.insert);
      }
    }
    return all;
  }

  // Those that go on from what's typed, a step at a time: `cpu.` shows `cpu.usage` and
  // `cpu.load`, and `di` shows `disk.` before what's in it.
  function matching(all, typed) {
    const seen = new Set();
    const shown = [];
    for (const each of all) {
      if (!each.label.startsWith(typed.text) || each.label === typed.text) continue;
      const rest = each.label.slice(typed.text.length);
      const step = rest.indexOf(".", 1);
      const suggestion =
        step > 0 && typed.kind === "name"
          ? { label: typed.text + rest.slice(0, step + 1), about: "", insert: typed.text + rest.slice(0, step + 1), more: true }
          : each;
      if (seen.has(suggestion.label)) continue;
      seen.add(suggestion.label);
      shown.push(suggestion);
      if (shown.length === MAX_SHOWN) break;
    }
    return shown;
  }

  function listFor(input) {
    if (list && field === input) return list;
    close();
    field = input;
    numbered += 1;
    list = document.createElement("ul");
    list.className = "cel-suggestions";
    list.id = `cel-suggestions-${numbered}`;
    list.setAttribute("role", "listbox");
    list.setAttribute("aria-label", "Suggestions");
    list.hidden = true;
    list.addEventListener("mousedown", (event) => {
      // On press rather than click, as pressing takes the focus out of the field.
      event.preventDefault();
      const item = event.target.closest("li");
      if (item) choose([...list.children].indexOf(item));
    });
    input.setAttribute("role", "combobox");
    input.setAttribute("aria-autocomplete", "list");
    input.setAttribute("aria-controls", list.id);
    input.setAttribute("aria-expanded", "false");
    input.parentElement.classList.add("cel-host");
    input.after(list);
    return list;
  }

  function close() {
    found = [];
    active = -1;
    if (list) list.remove();
    if (field) {
      field.setAttribute("aria-expanded", "false");
      field.removeAttribute("aria-activedescendant");
    }
    list = null;
    field = null;
  }

  function show(input, shown) {
    if (shown.length === 0) {
      close();
      return;
    }
    const box = listFor(input);
    found = shown;
    active = -1;
    box.replaceChildren(
      ...shown.map((suggestion, index) => {
        const item = document.createElement("li");
        item.id = `${box.id}-${index}`;
        item.setAttribute("role", "option");
        item.setAttribute("aria-selected", "false");
        item.append(suggestion.label);
        if (suggestion.about) {
          const about = document.createElement("span");
          about.textContent = suggestion.about;
          item.append(about);
        }
        return item;
      }),
    );
    // Just under the field, wherever it sits in its label.
    box.style.top = `${input.offsetTop + input.offsetHeight + 4}px`;
    box.hidden = false;
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
        field.setAttribute("aria-activedescendant", item.id);
      }
    });
  }

  async function suggest(input) {
    if (!(await load()) || document.activeElement !== input) return;
    const typed = typedAt(input);
    if (!typed || (typed.kind === "name" && typed.text === "")) {
      close();
      return;
    }
    show(input, matching(candidates(input, typed), typed));
  }

  function choose(index) {
    const input = field;
    const suggestion = found[index];
    const typed = typedAt(input);
    if (!suggestion || !typed) return;
    const before = input.value.slice(0, typed.start);
    const after = input.value.slice(input.selectionStart ?? input.value.length);
    const finished = before + suggestion.insert;
    input.value = finished + after;
    input.setSelectionRange(finished.length, finished.length);
    close();
    // A step through the dots, or a metric with fixed series, has more to pick from.
    if (suggestion.more || suggestion.insert.endsWith(".")) suggest(input);
  }

  document.addEventListener("focusin", (event) => {
    if (event.target.matches?.("input[data-cel]")) load();
  });
  document.addEventListener("input", (event) => {
    if (event.target.matches?.("input[data-cel]")) suggest(event.target);
  });
  document.addEventListener("focusout", (event) => {
    if (event.target === field) close();
  });
  document.addEventListener(
    "keydown",
    (event) => {
      if (!field || event.target !== field || found.length === 0) return;
      if (event.key === "ArrowDown") {
        event.preventDefault();
        highlight((active + 1) % found.length);
      } else if (event.key === "ArrowUp") {
        event.preventDefault();
        highlight((active - 1 + found.length) % found.length);
      } else if (event.key === "Escape") {
        event.preventDefault();
        close();
      } else if (event.key === "Enter" && active >= 0) {
        event.preventDefault();
        choose(active);
      } else if (event.key === "Tab") {
        event.preventDefault();
        choose(active >= 0 ? active : 0);
      }
    },
    true,
  );
})();
