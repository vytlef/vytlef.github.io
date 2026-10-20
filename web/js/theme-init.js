(function () {
  try {
    var t = localStorage.getItem("cryptopic:theme");
    if (t !== "dark" && t !== "light") {
      t = matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    }
    document.documentElement.dataset.theme = t;
    var meta = document.getElementById("theme-color-meta");
    if (meta) meta.content = t === "dark" ? "#0e1424" : "#f4f6fb";
  } catch (e) {}
})();
