document.querySelectorAll("details.ev").forEach(function (d) {
  var input = d.querySelector(".filter"), items = d.querySelectorAll("li");
  if (!input) return;
  input.hidden = false;
  input.addEventListener("input", function () {
    var q = input.value.trim().toLowerCase();
    items.forEach(function (li) { li.hidden = q !== "" && li.getAttribute("data-k").indexOf(q) < 0; });
  });
});
function openTarget() {
  var t = location.hash && document.getElementById(location.hash.slice(1));
  if (t && t.tagName === "DETAILS") t.open = true;
}
window.addEventListener("hashchange", openTarget);
openTarget();
