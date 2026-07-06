// Client-side mermaid render for LOCAL PREVIEW (preprocessor-free).
// The mdbook-mermaid preprocessor was skipped (version skew vs this mdbook); instead we
// convert mdbook's ```mermaid output (<pre><code class="language-mermaid">) into
// <div class="mermaid"> and render with the bundled mermaid.min.js. Theme follows mdbook.
(function () {
  function pickTheme() {
    var darkThemes = ['ayu', 'navy', 'coal'];
    var cl = document.getElementsByTagName('html')[0].classList;
    for (var i = 0; i < darkThemes.length; i++) { if (cl.contains(darkThemes[i])) return 'dark'; }
    return 'default';
  }
  function init() {
    var blocks = document.querySelectorAll('code.language-mermaid');
    Array.prototype.forEach.call(blocks, function (code) {
      var pre = (code.parentElement && code.parentElement.tagName === 'PRE') ? code.parentElement : code;
      var div = document.createElement('div');
      div.className = 'mermaid';
      div.textContent = code.textContent;
      pre.parentNode.replaceChild(div, pre);
    });
    if (window.mermaid) {
      try { window.mermaid.initialize({ startOnLoad: false, theme: pickTheme(), securityLevel: 'loose' }); } catch (e) {}
      try { window.mermaid.run(); } catch (e) { try { window.mermaid.init(); } catch (e2) {} }
    }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
