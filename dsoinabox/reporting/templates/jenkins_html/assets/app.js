// Progressive enhancement only - page works fully without this script
// This script provides optional UX enhancements but is not required
(function() {
  // Feature detect
  if (typeof document === 'undefined' || !document.addEventListener) {
    return;
  }

  // Optional: Add expand all / collapse all functionality if toolbar exists
  // This is purely optional - the page works without it
  const toolbar = document.querySelector('[data-controls="collapsibles"]');
  if (toolbar) {
    const blocks = Array.from(document.querySelectorAll('details.row-details-block'));
    if (blocks.length > 0) {
      toolbar.addEventListener('click', function(e) {
        const button = e.target.closest('[data-action]');
        if (!button) return;
        
        const action = button.getAttribute('data-action');
        const open = action === 'expand-all';
        
        blocks.forEach(function(details) {
          details.open = open;
        });
      });
    }
  }
})();
