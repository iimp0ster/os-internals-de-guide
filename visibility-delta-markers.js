// Visibility-delta tables use CSS pixel marks instead of platform emoji. Other tables retain
// their OS sprites and ordinary text markers.
(function () {
  var marks = {
    '✅': ['vis-pixel-positive', 'available'],
    '⚠': ['vis-pixel-partial', 'partial'],
    '⚠️': ['vis-pixel-partial', 'partial'],
    '❌': ['vis-pixel-blind', 'not available']
  };

  function replaceMarks(table) {
    var walker = document.createTreeWalker(table, NodeFilter.SHOW_TEXT);
    var nodes = [];
    var node;
    while ((node = walker.nextNode())) nodes.push(node);

    nodes.forEach(function (textNode) {
      if (!/[✅⚠❌]/.test(textNode.nodeValue) || /^(CODE|PRE|SCRIPT|STYLE)$/.test(textNode.parentElement.tagName)) return;
      var fragment = document.createDocumentFragment();
      textNode.nodeValue.split(/(✅|⚠️|⚠|❌)/g).forEach(function (part) {
        if (marks[part]) {
          var mark = document.createElement('span');
          mark.className = 'vis-pixel ' + marks[part][0];
          mark.setAttribute('aria-label', marks[part][1]);
          mark.setAttribute('role', 'img');
          fragment.appendChild(mark);
        } else if (part) {
          fragment.appendChild(document.createTextNode(part));
        }
      });
      textNode.parentNode.replaceChild(fragment, textNode);
    });
  }

  function init() {
    var tables = document.querySelectorAll('.table-wrapper table');
    Array.prototype.forEach.call(tables, function (table) {
      var firstHeader = table.querySelector('thead th');
      if (firstHeader && firstHeader.textContent.trim() === 'Graph element') replaceMarks(table);
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
