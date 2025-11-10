// Main JavaScript for CAKRA Web Interface

// Global utilities
window.CAKRA = {
    // API base URL
    API_BASE: '/api/v1',
    
    // Common utilities
    utils: {
        // Format date for display
        formatDate: function(dateString) {
            const date = new Date(dateString);
            return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
        },
        
        // Format file size
        formatFileSize: function(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        },
        
        // Debounce function
        debounce: function(func, wait) {
            let timeout;
            return function executedFunction(...args) {
                const later = () => {
                    clearTimeout(timeout);
                    func(...args);
                };
                clearTimeout(timeout);
                timeout = setTimeout(later, wait);
            };
        },
        
        // Show notification
        showNotification: function(message, type = 'info') {
            const alertClass = `alert-${type}`;
            const alert = document.createElement('div');
            alert.className = `alert ${alertClass} alert-dismissible fade show position-fixed`;
            alert.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
            alert.innerHTML = `
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            `;
            document.body.appendChild(alert);
            
            // Auto-remove after 5 seconds
            setTimeout(() => {
                if (alert.parentNode) {
                    alert.remove();
                }
            }, 5000);
        },
        
        // Copy to clipboard
        copyToClipboard: function(text) {
            navigator.clipboard.writeText(text).then(() => {
                this.showNotification('Copied to clipboard!', 'success');
            }).catch(err => {
                console.error('Failed to copy: ', err);
                this.showNotification('Failed to copy to clipboard', 'danger');
            });
        }
    },
    
    // API helpers
    api: {
        // Generic API request
        request: async function(endpoint, options = {}) {
            const url = `${CAKRA.API_BASE}${endpoint}`;
            const defaultOptions = {
                headers: {
                    'Content-Type': 'application/json',
                }
            };
            
            const config = { ...defaultOptions, ...options };
            
            try {
                const response = await fetch(url, config);
                const data = await response.json();
                
                if (!response.ok) {
                    throw new Error(data.detail || `HTTP ${response.status}`);
                }
                
                return data;
            } catch (error) {
                console.error('API request failed:', error);
                throw error;
            }
        },
        
        // Get health status
        getHealth: function() {
            return this.request('/health');
        },
        
        // Get statistics
        getStatistics: function() {
            return this.request('/statistics');
        },
        
        // Get scan results
        getScanResults: function(params = {}) {
            const query = new URLSearchParams(params).toString();
            return this.request(`/scan-results${query ? '?' + query : ''}`);
        },
        
        // Get payment channels
        getPaymentChannels: function(params = {}) {
            const query = new URLSearchParams(params).toString();
            return this.request(`/payment-channels${query ? '?' + query : ''}`);
        },
        
        // Scan URL
        scanUrl: function(url, priority = 'normal') {
            const formData = new FormData();
            formData.append('url', url);
            formData.append('priority', priority);
            
            return fetch(`${this.API_BASE}/scan`, {
                method: 'POST',
                body: formData
            }).then(response => response.json());
        }
    },
    
    // Chart utilities
    charts: {
        // Common chart options
        getDefaultOptions: function() {
            return {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: {
                            color: '#f8f9fa'
                        }
                    }
                },
                scales: {
                    x: {
                        ticks: { color: '#adb5bd' },
                        grid: { color: '#495057' }
                    },
                    y: {
                        ticks: { color: '#adb5bd' },
                        grid: { color: '#495057' }
                    }
                }
            };
        },
        
        // Create risk distribution chart
        createRiskChart: function(canvas, data) {
            if (typeof Chart === 'undefined') {
                console.warn('Chart.js not loaded');
                return null;
            }
            
            return new Chart(canvas, {
                type: 'doughnut',
                data: {
                    labels: ['Low Risk', 'Medium Risk', 'High Risk'],
                    datasets: [{
                        data: [data.low || 0, data.medium || 0, data.high || 0],
                        backgroundColor: ['#00875a', '#ffab00', '#de350b'],
                        borderWidth: 2,
                        borderColor: '#1b263b'
                    }]
                },
                options: {
                    ...this.getDefaultOptions(),
                    cutout: '60%'
                }
            });
        }
    }
};

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function(popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
    
    // Add loading states to forms
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function() {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                const originalText = submitBtn.innerHTML;
                submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Processing...';
                
                // Re-enable after 30 seconds as fallback
                setTimeout(() => {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = originalText;
                }, 30000);
            }
        });
    });
    
    // Add copy functionality to code blocks
    const codeBlocks = document.querySelectorAll('pre, code');
    codeBlocks.forEach(block => {
        if (block.textContent.length > 20) {
            block.style.position = 'relative';
            const copyBtn = document.createElement('button');
            copyBtn.className = 'btn btn-sm btn-outline-secondary position-absolute';
            copyBtn.style.cssText = 'top: 10px; right: 10px; z-index: 10;';
            copyBtn.innerHTML = '<i class="fas fa-copy"></i>';
            copyBtn.onclick = () => CAKRA.utils.copyToClipboard(block.textContent);
            block.appendChild(copyBtn);
        }
    });
    
    // Auto-refresh for real-time pages
    if (document.body.dataset.autoRefresh) {
        const interval = parseInt(document.body.dataset.autoRefresh) || 30000;
        setInterval(() => {
            if (document.visibilityState === 'visible') {
                location.reload();
            }
        }, interval);
    }
    
    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
    
    // Add search functionality to tables
    const searchInputs = document.querySelectorAll('[data-table-search]');
    searchInputs.forEach(input => {
        const tableId = input.dataset.tableSearch;
        const table = document.getElementById(tableId);
        if (table) {
            input.addEventListener('input', CAKRA.utils.debounce(function() {
                const searchTerm = this.value.toLowerCase();
                const rows = table.querySelectorAll('tbody tr');
                
                rows.forEach(row => {
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(searchTerm) ? '' : 'none';
                });
            }, 300));
        }
    });
});

// Handle connection errors
window.addEventListener('online', () => {
    CAKRA.utils.showNotification('Connection restored', 'success');
});

window.addEventListener('offline', () => {
    CAKRA.utils.showNotification('Connection lost', 'warning');
});

// Global error handler
window.addEventListener('error', (event) => {
    console.error('Global error:', event.error);
    CAKRA.utils.showNotification('An unexpected error occurred', 'danger');
});

// Unhandled promise rejection handler
window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
    CAKRA.utils.showNotification('An unexpected error occurred', 'danger');
    event.preventDefault();
});

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CAKRA;
}