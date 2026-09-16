// [DAN] BRIDGE DASHBOARD — dot-matrix icons, copied deliberately (same "copy, don't cross-repo-depend"
// discipline as style.css's own fonts/tokens) from DAN's own
// internal brand-pack source of truth, not cross-repo-linked. Only the three concepts this page
// actually uses are ported, not the whole matched-icon-set library — this is a static site with
// three fixed section headers, not a product that needs the full icon vocabulary.
(function () {
  var RED = "#f25b4f";
  var ACCENT = { on: "currentColor", red: RED };

  // [name, 7x7 dot bitmap, accent] — exact bitmaps copied from the canonical source, not redrawn.
  var ICONS = {
    chat:   { rows: ["0000000","1111110","1000010","1000010","1100110","0011000","0000000"], accent: "red" },
    people: { rows: ["0100010","1110111","0000000","0100010","1110111","1111111","0000000"], accent: "on" },
    mesh:   { rows: ["1000001","0100010","0010100","0001000","0010100","0100010","1000001"], accent: "on" },
  };

  function dot(name, px) {
    var e = ICONS[name];
    if (!e) return "";
    px = px || 12;
    var acc = ACCENT[e.accent] || "currentColor";
    var cols = e.rows[0].length;
    var gap = Math.max(1, Math.round(px * 0.42));
    var out = '<span class="dan-idg" style="grid-template-columns:repeat(' + cols + ',' + px + 'px);gap:' + gap + 'px">';
    e.rows.join("").split("").forEach(function (c) {
      var fill = c === "1" ? acc : null;
      out += '<i class="dan-idp" style="width:' + px + 'px;height:' + px + 'px;' +
        (fill ? "background:" + fill : "box-shadow:inset 0 0 0 1px rgba(128,128,128,.30)") + '"></i>';
    });
    return out + "</span>";
  }

  window.DANIcons = { dot: dot };


  // [DAN] brand favicon — red brackets · white DAN · charcoal ground. Injected from this one
  // shared script so every page carries the mark without a per-file <link> to forget.
  (function () {
    if (document.querySelector('link[rel="icon"]')) return;
    var svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">' +
      '<rect width="64" height="64" rx="13" fill="#1e1e22"/>' +
      '<text x="32" y="41" text-anchor="middle" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-weight="800" font-size="21" letter-spacing="-1">' +
      '<tspan fill="#f25b4f">[</tspan><tspan fill="#ffffff">DAN</tspan><tspan fill="#f25b4f">]</tspan>' +
      '</text></svg>';
    var link = document.createElement("link");
    link.rel = "icon"; link.type = "image/svg+xml";
    link.href = "data:image/svg+xml," + encodeURIComponent(svg);
    document.head.appendChild(link);
  })();
})();
