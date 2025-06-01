document.addEventListener('DOMContentLoaded', () => {
  console.log('Dashboard JS Loaded');

  // Tab navigation
  const tabLinks = document.querySelectorAll('#dashboardTabs a');
  const tabPanes = document.querySelectorAll('.tab-pane');
  if (tabLinks.length > 0 && tabPanes.length > 0) {
    console.log('Tab Links Found:', tabLinks.length);
    tabLinks.forEach(link => {
      link.addEventListener('click', (event) => {
        console.log('Tab Clicked:', link.getAttribute('href'));
        event.preventDefault();
        const targetId = link.getAttribute('href').substring(1); // e.g., 'active'
        // Remove active class from all links and panes
        tabLinks.forEach(l => l.classList.remove('active'));
        tabPanes.forEach(p => p.classList.remove('active'));
        // Add active class to clicked link and target pane
        link.classList.add('active');
        document.getElementById(targetId).classList.add('active');
      });
    });
  } else {
    console.error('Tabs or Panes Not Found:', { tabLinks: tabLinks.length, tabPanes: tabPanes.length });
  }

  // Debug duplicate Delete buttons
  const rows = document.querySelectorAll('#active tr[data-alias-id]');
  rows.forEach(row => {
    const aliasId = row.getAttribute('data-alias-id');
    const deleteButtonsInRow = row.querySelectorAll('button[data-delete-button]');
    console.log(`Row for Alias ID ${aliasId} has ${deleteButtonsInRow.length} Delete buttons`);
  });

  // Delete confirmation
  const deleteButtons = document.querySelectorAll('form[id^="delete-form-"] button[type="submit"]');
  console.log('Total Delete Buttons Found:', deleteButtons.length);
  deleteButtons.forEach(button => {
    button.addEventListener('click', (event) => {
      const form = button.closest('form');
      const alias = form.closest('tr').querySelector('td:first-child').textContent;
      console.log('Delete Button Clicked for Alias:', alias);
      const confirmed = confirm(`Are you sure you want to delete the alias ${alias}? This will mark it as inactive.`);
      if (!confirmed) {
        console.log('Delete Canceled for Alias:', alias);
        event.preventDefault();
      } else {
        console.log('Delete Confirmed for Alias:', alias);
      }
    });
  });

  // Dark Mode toggle
  const darkModeToggle = document.getElementById('darkModeToggle');
  if (darkModeToggle) {
    console.log('Dark Mode toggle found');
    darkModeToggle.addEventListener('click', () => {
      console.log('Dark Mode toggled');
      document.body.classList.toggle('dark-mode');
      localStorage.setItem('theme', document.body.classList.contains('dark-mode') ? 'dark' : 'light');
    });
  } else {
    console.error('Dark Mode toggle element not found');
  }

  // Apply saved theme
  if (localStorage.getItem('theme') === 'dark') {
    console.log('Applying saved dark theme');
    document.body.classList.add('dark-mode');
  }

  // Handle alias creation with loading state
  const createButton = document.getElementById('create-alias-btn');
  if (createButton) {
    console.log('Create alias button found');
    const form = createButton.closest('form');
    form.addEventListener('submit', (e) => {
      console.log('Create alias form submitted');
      createButton.disabled = true;
      createButton.textContent = 'Creating...';
    });
    window.addEventListener('pageshow', () => {
      console.log('Page shown, resetting create button');
      createButton.disabled = false;
      createButton.textContent = 'Create New Alias';
    });
  } else {
    console.error('Create alias button not found');
  }

  // Copy alias to clipboard
  const aliasCells = document.querySelectorAll('td:first-child');
  console.log('Alias cells found for copy:', aliasCells.length);
  aliasCells.forEach(cell => {
    cell.style.cursor = 'pointer';
    cell.addEventListener('click', () => {
      console.log('Copy alias clicked:', cell.textContent);
      const alias = cell.textContent;
      navigator.clipboard.writeText(alias).then(() => {
        alert('Alias copied to clipboard: ' + alias);
      }).catch(() => {
        alert('Failed to copy alias');
      });
    });
  });

  // Alias search
  const searchInput = document.createElement('input');
  searchInput.type = 'text';
  searchInput.placeholder = 'Search aliases...';
  searchInput.className = 'form-control mb-3';
  const tableResponsive = document.querySelector('.table-responsive');
  if (tableResponsive) {
    console.log('Table responsive found for search');
    tableResponsive.before(searchInput);
    searchInput.addEventListener('input', () => {
      console.log('Search input changed:', searchInput.value);
      const query = searchInput.value.toLowerCase();
      document.querySelectorAll('tbody tr').forEach(row => {
        const alias = row.cells[0].textContent.toLowerCase();
        const label = row.cells[1].textContent.toLowerCase();
        row.style.display = alias.includes(query) || label.includes(query) ? '' : 'none';
      });
    });
  } else {
    console.error('Table responsive element not found for search');
  }
});