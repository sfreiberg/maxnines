// Shows the value under the pointer on each chart.
for (const svg of document.querySelectorAll("svg[data-points]")) {
  const points = JSON.parse(svg.dataset.points);
  const cross = svg.querySelector(".cross");
  const dot = svg.querySelector(".dot");
  const tip = svg.parentElement.querySelector(".tip");

  const hide = () => {
    cross.setAttribute("hidden", "");
    dot.setAttribute("hidden", "");
    tip.hidden = true;
  };

  svg.addEventListener("pointermove", (event) => {
    const box = svg.getBoundingClientRect();
    const scale = svg.viewBox.baseVal.width / box.width;
    const x = (event.clientX - box.left) * scale;
    const nearest = points.reduce((best, point) =>
      Math.abs(point[0] - x) < Math.abs(best[0] - x) ? point : best,
    );
    cross.setAttribute("x1", nearest[0]);
    cross.setAttribute("x2", nearest[0]);
    dot.setAttribute("cx", nearest[0]);
    dot.setAttribute("cy", nearest[1]);
    cross.removeAttribute("hidden");
    dot.removeAttribute("hidden");
    tip.textContent = `${nearest[2]}  ${nearest[3]}`;
    tip.hidden = false;
    const left = nearest[0] / scale;
    const fits = left + tip.offsetWidth + 12 < box.width;
    tip.style.left = `${fits ? left + 10 : left - tip.offsetWidth - 10}px`;
  });
  svg.addEventListener("pointerleave", hide);
}
