// Snowflakes effect for winter months
function initSnowflakes() {
    const currentMonth = new Date().getMonth();
    if (currentMonth === 11 || currentMonth === 0 || currentMonth === 1) {
        new Snow();
    }
}

// Theme toggle functionality (common for all pages)
function initThemeToggle() {
    const themeToggle = document.getElementById('theme-toggle');
    const body = document.body;
    const currentTheme = localStorage.getItem('theme') || 'light';
    
    if (currentTheme === 'dark') {
        body.classList.add('dark-theme');
        themeToggle.textContent = '☀️';
    } else {
        themeToggle.textContent = '🌙';
    }
    
    themeToggle.addEventListener('click', () => {
        body.classList.toggle('dark-theme');
        const theme = body.classList.contains('dark-theme') ? 'dark' : 'light';
        localStorage.setItem('theme', theme);
        themeToggle.textContent = theme === 'dark' ? '☀️' : '🌙';
    });
}

// Form state management for check page
function initFormState() {
    const truthForm = document.getElementById('truthForm');
    if (!truthForm) return; // Skip if not on check page
    
    // Show loading when form is submitted
    truthForm.addEventListener('submit', function() {
        const loading = document.getElementById('loading');
        if (loading) {
            loading.style.display = 'block';
        }
    });
    
    // Save form state to localStorage
    function saveFormState() {
        const srcInput = document.getElementById('src');
        const dstInput = document.getElementById('dst');
        const portInput = document.getElementById('port');
        const filterSelect = document.getElementById('filter');
        
        if (!srcInput) return; // Skip if inputs don't exist
        
        const formData = {
            src: srcInput.value,
            dst: dstInput.value,
            port: portInput.value,
            filter: filterSelect.value
        };
        localStorage.setItem('checkFormState', JSON.stringify(formData));
    }
    
    // Restore form state from localStorage
    function restoreFormState() {
        try {
            const saved = localStorage.getItem('checkFormState');
            if (saved) {
                const formData = JSON.parse(saved);
                const srcInput = document.getElementById('src');
                const dstInput = document.getElementById('dst');
                const portInput = document.getElementById('port');
                const filterSelect = document.getElementById('filter');
                
                if (srcInput) srcInput.value = formData.src || '';
                if (dstInput) dstInput.value = formData.dst || '';
                if (portInput) portInput.value = formData.port || '';
                
                if (formData.filter && filterSelect) {
                    for (let i = 0; i < filterSelect.options.length; i++) {
                        if (filterSelect.options[i].value === formData.filter) {
                            filterSelect.selectedIndex = i;
                            break;
                        }
                    }
                }
            }
        } catch(e) {
            console.log('Error restoring form state:', e);
        }
    }
    
    // Attach event listeners to form fields
    document.querySelectorAll('#truthForm input, #truthForm select').forEach(function(element) {
        element.addEventListener('change', saveFormState);
        element.addEventListener('input', saveFormState);
    });
    
    // Restore state when page loads
    document.addEventListener('DOMContentLoaded', restoreFormState);
    restoreFormState(); // Also call immediately in case DOM is already loaded
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    initSnowflakes();
    initThemeToggle();
    initFormState();
});
