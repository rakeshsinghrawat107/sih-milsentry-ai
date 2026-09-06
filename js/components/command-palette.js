// CYBER CONSTELLATION — Command Palette (Ctrl+K)
// Global navigation and action system

window.CommandPalette = (() => {
  let isOpen = false;
  let selectedIdx = 0;
  let currentItems = [];
  let navigateFn = null;

  const COMMANDS = [
    // Navigation
    { label: 'Go to Dashboard',               icon: 'fa-gauge-high',        action: () => navigateFn('dashboard'),    category: 'Navigate' },
    { label: 'Start New Investigation',        icon: 'fa-magnifying-glass',  action: () => navigateFn('analyze'),      category: 'Navigate' },
    { label: 'View All Cases',                 icon: 'fa-folder-open',       action: () => navigateFn('cases'),        category: 'Navigate' },
    { label: 'Campaign Intelligence',          icon: 'fa-diagram-project',   action: () => navigateFn('campaigns'),    category: 'Navigate' },
    { label: 'Evidence Vault',                 icon: 'fa-lock',              action: () => navigateFn('evidence'),     category: 'Navigate' },
    { label: 'Forensic Report Builder',        icon: 'fa-file-lines',        action: () => navigateFn('reports'),      category: 'Navigate' },
    { label: 'Admin Console',                  icon: 'fa-sliders',           action: () => navigateFn('admin'),        category: 'Navigate' },
    // Demo Actions
    { label: 'LAUNCH DEMO Investigation',      icon: 'fa-rocket',            action: () => window.DemoMode && window.DemoMode.launchDemo(), category: 'Demo' },
    { label: 'Load Demo: CX-1024 (Phishing)',  icon: 'fa-triangle-exclamation', action: () => window.DemoMode && window.DemoMode.openCase('CX-1024'), category: 'Demo' },
    { label: 'Load Demo: CX-1023 (BEC)',       icon: 'fa-user-secret',       action: () => window.DemoMode && window.DemoMode.openCase('CX-1023'), category: 'Demo' },
    { label: 'Load Demo: CX-1021 (Creds)',     icon: 'fa-key',               action: () => window.DemoMode && window.DemoMode.openCase('CX-1021'), category: 'Demo' },
    { label: 'Load Demo: CX-1017 (Legitimate)',icon: 'fa-check-circle',      action: () => window.DemoMode && window.DemoMode.openCase('CX-1017'), category: 'Demo' },
    // View Actions
    { label: 'Switch to 3D Constellation',     icon: 'fa-cube',              action: () => window.GraphMode && window.GraphMode.set3D(),    category: 'View' },
    { label: 'Switch to 2D Graph',             icon: 'fa-diagram-project',   action: () => window.GraphMode && window.GraphMode.set2D(),    category: 'View' },
    { label: 'Open Threat Map',                icon: 'fa-earth-americas',    action: () => window.AppController && window.AppController.showMapPanel(), category: 'View' },
    // System
    { label: 'System Health Status',           icon: 'fa-heart-pulse',       action: () => navigateFn('admin'),        category: 'System' },
    { label: 'Generate Forensic Report',       icon: 'fa-file-export',       action: () => navigateFn('reports'),      category: 'System' },
    { label: 'Threat Intelligence Status',     icon: 'fa-shield-halved',     action: () => navigateFn('admin'),        category: 'System' },
  ];

  function init(navCallback) {
    navigateFn = navCallback;
    _buildDOM();
    _bindEvents();
  }

  function _buildDOM() {
    if (document.getElementById('command-palette-backdrop')) return;

    const backdrop = document.createElement('div');
    backdrop.id = 'command-palette-backdrop';
    backdrop.className = 'palette-backdrop';
    backdrop.setAttribute('role', 'dialog');
    backdrop.setAttribute('aria-modal', 'true');
    backdrop.setAttribute('aria-label', 'Command Palette');

    backdrop.innerHTML = `
      <div class="palette-modal" id="palette-modal">
        <div class="palette-input-wrap">
          <i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i>
          <input
            type="text"
            class="palette-input"
            id="palette-input"
            placeholder="Search commands, cases, domains, IPs..."
            autocomplete="off"
            spellcheck="false"
            aria-label="Command search"
          />
          <kbd class="search-kbd" aria-label="Press Escape to close">ESC</kbd>
        </div>
        <div class="palette-results" id="palette-results" role="listbox" aria-label="Command results"></div>
        <div class="palette-footer" aria-hidden="true">
          <span>↑↓ Navigate</span>
          <span>↵ Select</span>
          <span>ESC Close</span>
        </div>
      </div>
    `;

    document.body.appendChild(backdrop);
  }

  function _bindEvents() {
    // Keyboard shortcut
    document.addEventListener('keydown', (e) => {
      const isK = e.key === 'k' || e.key === 'K';
      if ((e.ctrlKey || e.metaKey) && isK) {
        e.preventDefault();
        isOpen ? close() : open();
        return;
      }

      if (!isOpen) return;

      switch (e.key) {
        case 'Escape': close(); break;
        case 'ArrowDown':
          e.preventDefault();
          selectedIdx = Math.min(selectedIdx + 1, currentItems.length - 1);
          _updateSelection();
          break;
        case 'ArrowUp':
          e.preventDefault();
          selectedIdx = Math.max(selectedIdx - 1, 0);
          _updateSelection();
          break;
        case 'Enter':
          e.preventDefault();
          _executeSelected();
          break;
      }
    });

    // Backdrop click to close
    document.getElementById('command-palette-backdrop').addEventListener('click', (e) => {
      if (!document.getElementById('palette-modal').contains(e.target)) close();
    });

    // Input handler
    const input = document.getElementById('palette-input');
    if (input) {
      input.addEventListener('input', () => _search(input.value));
    }
  }

  function open() {
    isOpen = true;
    selectedIdx = 0;
    const backdrop = document.getElementById('command-palette-backdrop');
    if (backdrop) {
      backdrop.classList.add('open');
      const input = document.getElementById('palette-input');
      if (input) { input.value = ''; input.focus(); }
      _renderItems(COMMANDS);
    }
  }

  function close() {
    isOpen = false;
    const backdrop = document.getElementById('command-palette-backdrop');
    if (backdrop) backdrop.classList.remove('open');
  }

  function _search(query) {
    if (!query.trim()) { _renderItems(COMMANDS); return; }

    const q = query.toLowerCase();
    const filtered = COMMANDS.filter(cmd =>
      cmd.label.toLowerCase().includes(q) ||
      cmd.category.toLowerCase().includes(q)
    );

    // Also match demo cases
    const caseMatches = (window.DEMO_CASES || [])
      .filter(c => c.id.toLowerCase().includes(q) || c.type.toLowerCase().includes(q) || c.subject.toLowerCase().includes(q))
      .slice(0, 3)
      .map(c => ({
        label: `Case ${c.id} — ${c.type} (Score: ${c.riskScore})`,
        icon: 'fa-folder-open',
        action: () => window.DemoMode && window.DemoMode.openCase(c.id),
        category: 'Cases'
      }));

    _renderItems([...filtered, ...caseMatches]);
  }

  function _renderItems(items) {
    currentItems = items;
    selectedIdx = 0;
    const container = document.getElementById('palette-results');
    if (!container) return;

    if (items.length === 0) {
      container.innerHTML = `<div class="empty-state" style="padding: 32px 20px;"><i class="fa-solid fa-magnifying-glass" style="font-size:1.5rem; margin-bottom:10px; opacity:0.3;"></i><p style="font-size:0.8rem; color:var(--text-muted);">No commands found</p></div>`;
      return;
    }

    // Group by category
    const groups = {};
    items.forEach(item => {
      if (!groups[item.category]) groups[item.category] = [];
      groups[item.category].push(item);
    });

    let html = '';
    let globalIdx = 0;

    Object.entries(groups).forEach(([cat, cmds]) => {
      html += `<div class="palette-section-label">${cat}</div>`;
      cmds.forEach((cmd, i) => {
        const idx = globalIdx++;
        html += `
          <div class="palette-item${idx === 0 ? ' selected' : ''}"
               data-idx="${idx}"
               role="option"
               aria-selected="${idx === 0}"
               tabindex="-1"
          >
            <i class="fa-solid ${cmd.icon}" aria-hidden="true"></i>
            <span>${cmd.label}</span>
          </div>
        `;
      });
    });

    container.innerHTML = html;

    // Bind clicks
    container.querySelectorAll('.palette-item').forEach(el => {
      el.addEventListener('click', () => {
        const idx = parseInt(el.dataset.idx);
        selectedIdx = idx;
        _executeSelected();
      });
    });
  }

  function _updateSelection() {
    const container = document.getElementById('palette-results');
    if (!container) return;

    container.querySelectorAll('.palette-item').forEach((el, i) => {
      el.classList.toggle('selected', i === selectedIdx);
      el.setAttribute('aria-selected', i === selectedIdx ? 'true' : 'false');
      if (i === selectedIdx) el.scrollIntoView({ block: 'nearest' });
    });
  }

  function _executeSelected() {
    if (currentItems[selectedIdx]) {
      close();
      setTimeout(() => { currentItems[selectedIdx].action(); }, 100);
    }
  }

  return { init, open, close };
})();
