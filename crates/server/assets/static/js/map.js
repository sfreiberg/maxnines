// Draws the Map page, and the map on the location form for picking a place. The
// outline of the world comes already projected from /assets/map/world.json. The Map
// page carries its sites in #map-data, which the page's own refresh keeps current.
// Agents choose their own names, so those are only ever set as text.
(() => {
  const canvas = document.getElementById("map-canvas");
  const picker = document.getElementById("map-picker");
  if (!canvas && !picker) return;

  // ---- Equal Earth, with the numbers data/generate.py drew the outline with.
  const A1 = 1.340264, A2 = -0.081106, A3 = 0.000893, A4 = 0.003796, M = Math.sqrt(3) / 2;
  const XMAX = Math.PI / (M * A1), WIDTH = 1000, SCALE = WIDTH / (2 * XMAX);
  const MAX_ZOOM = 40;

  function project(lon, lat) {
    const lam = (lon * Math.PI) / 180, phi = (lat * Math.PI) / 180;
    const t = Math.asin(M * Math.sin(phi)), t2 = t * t, t6 = t2 * t2 * t2;
    const x = (lam * Math.cos(t)) / (M * (A1 + 3 * A2 * t2 + t6 * (7 * A3 + 9 * A4 * t2)));
    const y = t * (A1 + A2 * t2 + t6 * (A3 + A4 * t2));
    return [(x + XMAX) * SCALE, -y * SCALE];
  }

  function unproject(px, py) {
    const x = px / SCALE - XMAX, y = -py / SCALE;
    let t = y / A1;
    for (let i = 0; i < 20; i += 1) {
      const t2 = t * t, t6 = t2 * t2 * t2;
      const step = (t * (A1 + A2 * t2 + t6 * (A3 + A4 * t2)) - y) / (A1 + 3 * A2 * t2 + t6 * (7 * A3 + 9 * A4 * t2));
      t -= step;
      if (Math.abs(step) < 1e-12) break;
    }
    const t2 = t * t, t6 = t2 * t2 * t2;
    const lon = (M * x * (A1 + 3 * A2 * t2 + t6 * (7 * A3 + 9 * A4 * t2))) / Math.cos(t);
    const lat = Math.asin(Math.sin(t) / M);
    return [(lon * 180) / Math.PI, (lat * 180) / Math.PI];
  }

  const NS = "http://www.w3.org/2000/svg";
  function svgEl(name, attrs = {}) {
    const node = document.createElementNS(NS, name);
    for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
    return node;
  }
  function htmlEl(name, className, text) {
    const node = document.createElement(name);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  async function loadWorld(url) {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`world ${response.status}`);
    return response.json();
  }

  // ---- A map that pans and zooms. Markers are drawn by `draw`, at the same size
  // on screen whatever the zoom.
  function createMap(container, world, title, draw) {
    const top = world.top, height = world.height, bottom = top + height;
    const svg = svgEl("svg", { viewBox: `0 ${top} ${WIDTH} ${height}`, class: "map-svg", role: "img" });
    const label = svgEl("title");
    label.textContent = title;
    const base = svgEl("g");
    base.append(
      svgEl("path", { class: "map-ocean", d: world.sphere }),
      svgEl("path", { class: "map-graticule", d: world.graticule }),
      svgEl("path", { class: "map-land", d: world.land }),
    );
    const overlay = svgEl("g");
    svg.append(label, base, overlay);

    const zoom = htmlEl("div", "map-zoom");
    const zoomIn = htmlEl("button", "", "+");
    const zoomOut = htmlEl("button", "", "−");
    zoomIn.type = zoomOut.type = "button";
    zoomIn.setAttribute("aria-label", "Zoom in");
    zoomOut.setAttribute("aria-label", "Zoom out");
    zoom.append(zoomIn, zoomOut);
    container.replaceChildren(svg, zoom);

    const map = {
      svg, overlay, container,
      view: { k: 1, tx: 0, ty: 0 },
      onClick: null,
      onMove: null,
      unitsPerPixel: () => WIDTH / svg.getBoundingClientRect().width,
      toView(clientX, clientY) {
        const box = svg.getBoundingClientRect();
        const u = WIDTH / box.width;
        return [(clientX - box.left) * u, top + (clientY - box.top) * u];
      },
      place(lon, lat) {
        const [x, y] = project(lon, lat);
        return [x * this.view.k + this.view.tx, y * this.view.k + this.view.ty];
      },
      // Where on screen a point in the view is, from the container's corner.
      toScreen(x, y) {
        const box = svg.getBoundingClientRect(), outer = container.getBoundingClientRect();
        const u = WIDTH / box.width;
        return [x / u + (box.left - outer.left), (y - top) / u + (box.top - outer.top)];
      },
      pointAt(clientX, clientY) {
        const [vx, vy] = this.toView(clientX, clientY);
        const [lon, lat] = unproject((vx - this.view.tx) / this.view.k, (vy - this.view.ty) / this.view.k);
        if (!Number.isFinite(lon) || !Number.isFinite(lat) || Math.abs(lon) > 180) return null;
        return [lon, Math.max(-90, Math.min(90, lat))];
      },
      redraw() {
        clamp();
        base.setAttribute("transform", `translate(${this.view.tx} ${this.view.ty}) scale(${this.view.k})`);
        draw(this);
      },
      zoomAt(x, y, factor) {
        const k = Math.min(Math.max(this.view.k * factor, 1), MAX_ZOOM);
        this.view.tx = x - (x - this.view.tx) * (k / this.view.k);
        this.view.ty = y - (y - this.view.ty) * (k / this.view.k);
        this.view.k = k;
        this.redraw();
      },
      fitView(x0, y0, x1, y1) {
        const k = Math.min(WIDTH / (x1 - x0), height / (y1 - y0)) * 0.9;
        this.view.k = Math.min(Math.max(k, 1), MAX_ZOOM);
        this.view.tx = WIDTH / 2 - ((x0 + x1) / 2) * this.view.k;
        this.view.ty = top + height / 2 - ((y0 + y1) / 2) * this.view.k;
        this.redraw();
      },
      fitLonLat(west, south, east, north) {
        const corners = [project(west, south), project(east, north), project(west, north), project(east, south)];
        const xs = corners.map((c) => c[0]), ys = corners.map((c) => c[1]);
        this.fitView(Math.min(...xs), Math.min(...ys), Math.max(...xs), Math.max(...ys));
      },
      centre(lon, lat, atLeast) {
        const [x, y] = project(lon, lat);
        this.view.k = Math.min(Math.max(this.view.k, atLeast), MAX_ZOOM);
        this.view.tx = WIDTH / 2 - x * this.view.k;
        this.view.ty = top + height / 2 - y * this.view.k;
        this.redraw();
      },
      reset() {
        this.view = { k: 1, tx: 0, ty: 0 };
        this.redraw();
      },
    };

    function clamp() {
      const v = map.view;
      v.k = Math.min(Math.max(v.k, 1), MAX_ZOOM);
      v.tx = Math.min(0, Math.max(WIDTH - WIDTH * v.k, v.tx));
      v.ty = Math.min(top * (1 - v.k), Math.max(bottom * (1 - v.k), v.ty));
    }

    const middle = () => [WIDTH / 2, top + height / 2];
    zoomIn.addEventListener("click", () => { map.zoomAt(...middle(), 1.6); map.onMove?.(); });
    zoomOut.addEventListener("click", () => { map.zoomAt(...middle(), 1 / 1.6); map.onMove?.(); });
    svg.addEventListener("wheel", (event) => {
      event.preventDefault();
      map.zoomAt(...map.toView(event.clientX, event.clientY), Math.exp(-event.deltaY * 0.0022));
      map.onMove?.();
    }, { passive: false });

    let drag = null;
    svg.addEventListener("pointerdown", (event) => {
      if (event.target.closest(".map-marker")) return;
      drag = { x: event.clientX, y: event.clientY, tx: map.view.tx, ty: map.view.ty, moved: false };
      svg.setPointerCapture(event.pointerId);
    });
    svg.addEventListener("pointermove", (event) => {
      if (!drag) return;
      const u = map.unitsPerPixel();
      const dx = (event.clientX - drag.x) * u, dy = (event.clientY - drag.y) * u;
      if (!drag.moved && Math.hypot(dx, dy) < 4 * u) return;
      if (!drag.moved) { drag.moved = true; svg.classList.add("dragging"); map.onMove?.(); }
      map.view.tx = drag.tx + dx;
      map.view.ty = drag.ty + dy;
      map.redraw();
    });
    const finish = (event) => {
      if (!drag) return;
      const clicked = !drag.moved;
      drag = null;
      svg.classList.remove("dragging");
      if (clicked && event.type === "pointerup") map.onClick?.(event.clientX, event.clientY);
    };
    svg.addEventListener("pointerup", finish);
    svg.addEventListener("pointercancel", finish);
    new ResizeObserver(() => map.redraw()).observe(svg);
    return map;
  }

  const HEALTH = ["critical", "warning", "offline", "online"];
  const people = new Intl.NumberFormat();

  // ---- The Map page.
  function showSites() {
    const read = () => {
      try {
        return JSON.parse(document.getElementById("map-data")?.dataset.map || "{}");
      } catch {
        return { sites: [], unplaced: [] };
      }
    };
    let data = read();
    let selected = null;
    let groups = [];
    const tooltip = htmlEl("div", "map-tooltip");
    tooltip.hidden = true;

    const radius = (total) => 5 + Math.sqrt(total) * 1.6;
    const total = (site) => HEALTH.reduce((sum, h) => sum + (site.counts[h] || 0), 0);
    const worst = (sites) => HEALTH.find((h) => sites.some((site) => site.health === h)) || "online";
    const siteById = (id) => data.sites.find((site) => site.rule_id === id);

    // Sites too close to tell apart at this zoom are drawn as one, where their
    // hosts are on average. A selected site always stands on its own.
    function cluster(map, u) {
      const found = [];
      const order = [...data.sites].sort((a, b) => total(b) - total(a));
      for (const site of order) {
        const [x, y] = map.place(site.longitude, site.latitude);
        const count = total(site);
        const r = radius(count) * u;
        const lone = site.rule_id === selected;
        const near = lone ? null : found.find((g) =>
          !g.members.some((m) => m.rule_id === selected) && Math.hypot(g.x - x, g.y - y) < g.r + r + 3 * u);
        if (!near) {
          found.push({ x, y, r, total: count, members: [site] });
          continue;
        }
        near.x = (near.x * near.total + x * count) / (near.total + count);
        near.y = (near.y * near.total + y * count) / (near.total + count);
        near.total += count;
        near.r = radius(near.total) * u;
        near.members.push(site);
      }
      return found;
    }

    function draw(map) {
      const u = map.unitsPerPixel();
      groups = cluster(map, u);
      const showNames = map.view.k >= 2.2;
      map.overlay.replaceChildren();
      for (const group of groups) {
        const merged = group.members.length > 1;
        const site = group.members[0];
        const health = merged ? worst(group.members) : site.health;
        const isSelected = !merged && site.rule_id === selected;
        const marker = svgEl("g", {
          class: `map-marker ${health}${isSelected ? " selected" : ""}`,
          transform: `translate(${group.x} ${group.y})`,
          tabindex: "0",
          role: "button",
        });
        marker.setAttribute("aria-label", merged
          ? `${group.members.length} sites with ${group.total} hosts`
          : `${site.name}, ${total(site)} hosts`);
        const ring = svgEl("circle", { class: "map-ring", r: group.r + 3.5 * u, "stroke-width": 2 * u });
        const dot = svgEl("circle", { class: "map-fill", r: group.r, "stroke-width": 2 * u });
        marker.append(ring, dot);
        if (group.total > 1) {
          const count = svgEl("text", { class: "map-count", "font-size": 10 * u });
          count.textContent = group.total;
          marker.append(count);
        }
        if (showNames || isSelected) {
          const name = svgEl("text", { class: "map-name", x: group.r + 6 * u, y: 4 * u, "font-size": 12 * u, "stroke-width": 3 * u });
          name.textContent = merged ? `${group.members.length} sites` : site.name;
          marker.append(name);
        }
        marker.addEventListener("pointerenter", () => showTip(map, group));
        marker.addEventListener("pointerleave", () => { if (!isSelected) hideTip(); });
        marker.addEventListener("focus", () => showTip(map, group));
        marker.addEventListener("blur", () => { if (!isSelected) hideTip(); });
        marker.addEventListener("click", (event) => { event.stopPropagation(); open(map, group); });
        marker.addEventListener("keydown", (event) => {
          if (event.key === "Enter" || event.key === " ") { event.preventDefault(); open(map, group); }
        });
        map.overlay.append(marker);
      }
      const chosen = groups.find((g) => g.members.length === 1 && g.members[0].rule_id === selected);
      if (chosen) showTip(map, chosen);
    }

    function hostLine(host) {
      const line = htmlEl("li");
      line.append(htmlEl("span", `map-dot ${host.health}`), htmlEl("span", "", host.hostname), htmlEl("span", "host-id", host.short_id));
      return line;
    }

    function showTip(map, group) {
      tooltip.replaceChildren();
      if (group.members.length > 1) {
        tooltip.append(htmlEl("h3", "", `${group.members.length} sites close together`), htmlEl("p", "", `${group.total} hosts`));
        const list = htmlEl("ul");
        for (const site of group.members) {
          const line = htmlEl("li");
          line.append(htmlEl("span", `map-dot ${site.health}`), htmlEl("span", "", site.name), htmlEl("span", "host-id", String(total(site))));
          list.append(line);
        }
        tooltip.append(list, htmlEl("p", "map-tip-hint", "Click to zoom in."));
      } else {
        const site = group.members[0];
        const counts = HEALTH.filter((h) => site.counts[h]).map((h) => `${site.counts[h]} ${h}`).join(" · ");
        tooltip.append(htmlEl("h3", "", site.name), htmlEl("p", "", counts));
        if (site.place) tooltip.append(htmlEl("p", "map-tip-place", site.place));
        const list = htmlEl("ul");
        for (const host of site.hosts.slice(0, 6)) list.append(hostLine(host));
        tooltip.append(list);
        if (site.hosts.length > 6) tooltip.append(htmlEl("p", "map-tip-hint", `and ${site.hosts.length - 6} more`));
      }
      tooltip.hidden = false;
      const [sx, sy] = map.toScreen(group.x, group.y);
      const outer = canvas.getBoundingClientRect();
      const width = tooltip.offsetWidth, height = tooltip.offsetHeight;
      let left = sx + 16;
      if (left + width > outer.width - 8) left = sx - width - 16;
      tooltip.style.left = `${Math.max(8, left)}px`;
      tooltip.style.top = `${Math.min(Math.max(8, sy - height / 2), outer.height - height - 8)}px`;
    }
    function hideTip() { tooltip.hidden = true; }

    function markList() {
      for (const button of document.querySelectorAll(".map-site")) {
        button.setAttribute("aria-current", String(Number(button.dataset.rule) === selected));
      }
    }

    function open(map, group) {
      clearRegion();
      if (group.members.length > 1) {
        hideTip();
        const points = group.members.map((site) => project(site.longitude, site.latitude));
        const xs = points.map((p) => p[0]), ys = points.map((p) => p[1]);
        map.fitView(Math.min(...xs) - 3, Math.min(...ys) - 3, Math.max(...xs) + 3, Math.max(...ys) + 3);
        return;
      }
      select(map, group.members[0].rule_id, false);
    }

    function select(map, id, zoom) {
      selected = id;
      markList();
      const site = id === null ? null : siteById(id);
      if (site && zoom) {
        clearRegion();
        map.centre(site.longitude, site.latitude, 8);
      } else {
        map.redraw();
      }
      if (!site) hideTip();
    }

    const REGIONS = {
      europe: [-12, 35, 32, 62],
      americas: [-128, 18, -60, 56],
      apac: [95, -45, 160, 45],
    };
    const regionButtons = document.querySelectorAll(".map-regions button");
    function clearRegion() {
      for (const button of regionButtons) button.setAttribute("aria-pressed", "false");
    }

    loadWorld(canvas.dataset.world)
      .then((world) => {
        const map = createMap(canvas, world, "Sites on a map of the world, coloured by how they're doing", draw);
        canvas.append(tooltip);
        map.onClick = () => select(map, null, false);
        map.onMove = clearRegion;
        map.redraw();
        for (const button of regionButtons) {
          button.addEventListener("click", () => {
            for (const other of regionButtons) other.setAttribute("aria-pressed", String(other === button));
            const box = REGIONS[button.dataset.region];
            if (box) map.fitLonLat(...box); else map.reset();
            hideTip();
          });
        }
        document.addEventListener("click", (event) => {
          const button = event.target.closest(".map-site");
          if (button) select(map, Number(button.dataset.rule), true);
        });
        // The page refreshes itself in place, and #map-data with it.
        document.addEventListener("htmx:afterSettle", () => {
          data = read();
          if (selected !== null && !siteById(selected)) selected = null;
          markList();
          map.redraw();
        });
      })
      .catch(() => {
        const hint = canvas.querySelector(".hint");
        if (hint) hint.textContent = "The map's outline didn't load. The sites are listed beside it.";
      });
  }

  // ---- The location form: search for a place, or click the map.
  function pickPlaces() {
    const search = document.getElementById("place-search");
    const options = document.getElementById("place-options");
    const status = document.getElementById("place-status");
    const place = document.getElementById("place");
    const latitude = document.getElementById("latitude");
    const longitude = document.getElementById("longitude");
    let map = null;
    let found = [];
    let active = -1;
    let timer = null;
    let request = null;

    const point = () => {
      const lat = Number.parseFloat(latitude.value), lon = Number.parseFloat(longitude.value);
      return Math.abs(lat) <= 90 && Math.abs(lon) <= 180 ? [lon, lat] : null;
    };

    function drawPin(view) {
      view.overlay.replaceChildren();
      const at = point();
      if (!at) return;
      const u = view.unitsPerPixel();
      const [x, y] = view.place(...at);
      const pin = svgEl("g", { class: "map-pin", transform: `translate(${x} ${y})` });
      pin.append(
        svgEl("circle", { class: "map-reach", r: 13 * u, "stroke-width": 1.5 * u }),
        svgEl("circle", { class: "map-core", r: 6 * u, "stroke-width": 2 * u }),
      );
      view.overlay.append(pin);
    }

    function setPoint(lat, lon) {
      latitude.value = lat.toFixed(4);
      longitude.value = lon.toFixed(4);
    }

    function say(...parts) {
      status.replaceChildren(...parts);
    }

    function close() {
      found = [];
      active = -1;
      options.hidden = true;
      options.replaceChildren();
      search.setAttribute("aria-expanded", "false");
      search.removeAttribute("aria-activedescendant");
    }

    function highlight(index) {
      active = index;
      [...options.children].forEach((item, position) => {
        item.classList.toggle("active", position === index);
        item.setAttribute("aria-selected", String(position === index));
        if (position === index) {
          item.scrollIntoView({ block: "nearest" });
          search.setAttribute("aria-activedescendant", item.id);
        }
      });
    }

    function show(places) {
      found = places;
      active = -1;
      if (!places.length) {
        close();
        say("No town or city by that name. Try a nearby one, or click the map.");
        return;
      }
      options.replaceChildren(...places.map((item, index) => {
        const line = htmlEl("li");
        line.id = `place-option-${index}`;
        line.setAttribute("role", "option");
        line.setAttribute("aria-selected", "false");
        const where = [item.region, item.country].filter(Boolean).join(", ");
        line.append(
          htmlEl("span", "place-name", item.name),
          htmlEl("span", "place-people", item.population ? `${people.format(item.population)} people` : ""),
          htmlEl("span", "place-where", where),
        );
        return line;
      }));
      options.hidden = false;
      search.setAttribute("aria-expanded", "true");
    }

    function choose(item) {
      search.value = item.label;
      place.value = item.label;
      setPoint(item.latitude, item.longitude);
      close();
      say("Put at ", htmlEl("b", "", item.label), ".");
      map?.centre(item.longitude, item.latitude, 8);
    }

    async function lookUp() {
      request?.abort();
      const text = search.value.trim();
      if (text.length < 2) { close(); return; }
      request = new AbortController();
      try {
        const response = await fetch(`/map/places?q=${encodeURIComponent(text)}`, { signal: request.signal });
        if (response.ok && document.activeElement === search) show(await response.json());
      } catch (error) {
        if (error.name !== "AbortError") close();
      }
    }

    search.addEventListener("input", () => {
      // Whatever's typed is the place's name, unless a suggestion is chosen.
      place.value = search.value.trim();
      clearTimeout(timer);
      timer = setTimeout(lookUp, 150);
    });
    search.addEventListener("keydown", (event) => {
      const open = found.length > 0;
      if (event.key === "ArrowDown" && open) {
        event.preventDefault();
        highlight((active + 1) % found.length);
      } else if (event.key === "ArrowUp" && open) {
        event.preventDefault();
        highlight((active - 1 + found.length) % found.length);
      } else if (event.key === "Enter" && open) {
        event.preventDefault();
        choose(found[Math.max(active, 0)]);
      } else if (event.key === "Escape" && open) {
        event.preventDefault();
        close();
      }
    });
    search.addEventListener("blur", () => setTimeout(close, 150));
    options.addEventListener("mousedown", (event) => {
      event.preventDefault();
      const item = event.target.closest("li");
      if (item) choose(found[[...options.children].indexOf(item)]);
    });
    for (const input of [latitude, longitude]) {
      input.addEventListener("input", () => map?.redraw());
    }

    loadWorld(picker.dataset.world)
      .then((world) => {
        map = createMap(picker, world, "A map of the world for picking where these hosts are", drawPin);
        map.svg.classList.add("picking");
        map.onClick = async (clientX, clientY) => {
          const at = map.pointAt(clientX, clientY);
          if (!at) return;
          setPoint(at[1], at[0]);
          map.redraw();
          try {
            const response = await fetch(`/map/nearest?lat=${at[1]}&lon=${at[0]}`);
            const near = response.ok ? await response.json() : null;
            if (near) {
              search.value = near.label;
              place.value = near.label;
              say("Near ", htmlEl("b", "", near.label), ". Change the name above if you like.");
            }
          } catch {
            // The point is set either way; only its name is missing.
          }
        };
        const at = point();
        if (at) map.centre(at[0], at[1], 6); else map.redraw();
      })
      .catch(() => {
        const hint = picker.querySelector(".hint");
        if (hint) hint.textContent = "The map didn't load. Search for a place, or type the coordinates.";
      });
  }

  if (canvas) showSites();
  if (picker) pickPlaces();
})();
