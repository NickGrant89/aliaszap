// Confirm deletion
document.querySelectorAll('button[data-alias-id]').forEach(button => {
  button.addEventListener('click', (e) => {
    if (!confirm('Are you sure you want to delete this alias?')) {
      e.preventDefault();
    }
  });
});

// Handle alias creation with loading state
const createButton = document.getElementById('create-alias-btn');
if (createButton) {
  createButton.addEventListener('click', (e) => {
    createButton.disabled = true;
    createButton.textContent = 'Creating...';
  });
});

// Copy alias to clipboard
document.querySelectorAll('td:first-child').forEach(cell => {
  cell.style.cursor = 'pointer';
  cell.addEventListener('click', () => {
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
document.querySelector('.table-responsive')?.before(searchInput);
searchInput.addEventListener('input', () => {
  const query = searchInput.value.toLowerCase();
  document.querySelectorAll('tbody tr').forEach(row => {
    const alias = row.cells[0].textContent.toLowerCase();
    const label = row.cells[1].textContent.toLowerCase();
    row.style.display = alias.includes(query) || label.includes(query) ? '' : 'none';
  });
});