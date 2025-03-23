document.addEventListener('DOMContentLoaded', function() {
    const scanForm = document.getElementById('scanForm');
    const startScanBtn = document.getElementById('startScanBtn');
    const scanProgressModal = new bootstrap.Modal(document.getElementById('scanProgressModal'));
    const scanProgressBar = document.getElementById('scanProgressBar');
    const scanStatus = document.getElementById('scanStatus');
    const modalTarget = document.getElementById('modalTarget');
    const viewResultsBtn = document.getElementById('viewResultsBtn');
    const startNewBtn = document.getElementById('startNewBtn');
    
    let currentScanId = null;
    let scanStatusInterval = null;
    
    // Form submission handler
    scanForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const target = document.getElementById('target').value.trim();
        const toolCheckboxes = document.querySelectorAll('input[name="tools"]:checked');
        
        if (!target) {
            showAlert('Target domain/IP is required', 'danger');
            return;
        }
        
        if (toolCheckboxes.length === 0) {
            showAlert('At least one tool must be selected', 'danger');
            return;
        }
        
        const formData = new FormData(scanForm);
        startScanBtn.disabled = true;
        startScanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Starting scan...';
        
        // Start the scan
        fetch('/start_scan', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            startScanBtn.disabled = false;
            startScanBtn.innerHTML = '<i class="fas fa-play-circle"></i> Start Scan';
            
            if (data.status === 'success') {
                currentScanId = data.scan_id;
                modalTarget.textContent = target;
                
                // Show progress modal
                scanProgressModal.show();
                
                // Start checking scan status
                scanStatusInterval = setInterval(checkScanStatus, 2000);
            } else {
                showAlert(data.message || 'Failed to start scan', 'danger');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            startScanBtn.disabled = false;
            startScanBtn.innerHTML = '<i class="fas fa-play-circle"></i> Start Scan';
            showAlert('Network error occurred', 'danger');
        });
    });
    
    // Function to check scan status
    function checkScanStatus() {
        if (!currentScanId) return;
        
        fetch(`/scan_status/${currentScanId}`)
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    const scanData = data.data;
                    
                    // Update progress bar
                    scanProgressBar.style.width = `${scanData.progress}%`;
                    scanProgressBar.textContent = `${scanData.progress}%`;
                    scanProgressBar.setAttribute('aria-valuenow', scanData.progress);
                    
                    // Update status text
                    if (scanData.scan_status === 'running') {
                        scanStatus.innerHTML = `
                            <p class="text-center text-info">
                                <i class="fas fa-spinner fa-spin"></i> Scan is running... (${scanData.progress}%)
                            </p>
                        `;
                    } else if (scanData.scan_status === 'completed') {
                        scanStatus.innerHTML = `
                            <p class="text-center text-success">
                                <i class="fas fa-check-circle"></i> Scan completed successfully!
                            </p>
                        `;
                        scanProgressBar.classList.remove('progress-bar-animated');
                        scanProgressBar.classList.remove('progress-bar-striped');
                        scanProgressBar.classList.add('bg-success');
                        
                        // Show result buttons
                        viewResultsBtn.style.display = 'block';
                        startNewBtn.style.display = 'block';
                        
                        // Stop checking status
                        clearInterval(scanStatusInterval);
                    } else if (scanData.scan_status === 'failed') {
                        scanStatus.innerHTML = `
                            <p class="text-center text-danger">
                                <i class="fas fa-exclamation-triangle"></i> Scan failed!
                            </p>
                        `;
                        scanProgressBar.classList.remove('progress-bar-animated');
                        scanProgressBar.classList.remove('progress-bar-striped');
                        scanProgressBar.classList.add('bg-danger');
                        
                        // Show result buttons
                        viewResultsBtn.style.display = 'block';
                        startNewBtn.style.display = 'block';
                        
                        // Stop checking status
                        clearInterval(scanStatusInterval);
                    }
                } else {
                    console.error('Error checking scan status:', data.message);
                }
            })
            .catch(error => {
                console.error('Error:', error);
            });
    }
    
    // View results button handler
    viewResultsBtn.addEventListener('click', function() {
        if (currentScanId) {
            window.location.href = `/results/${currentScanId}`;
        }
    });
    
    // Start new scan button handler
    startNewBtn.addEventListener('click', function() {
        scanProgressModal.hide();
        currentScanId = null;
        clearInterval(scanStatusInterval);
        
        // Reset progress bar
        scanProgressBar.style.width = '0%';
        scanProgressBar.textContent = '0%';
        scanProgressBar.setAttribute('aria-valuenow', 0);
        scanProgressBar.classList.add('progress-bar-animated');
        scanProgressBar.classList.add('progress-bar-striped');
        scanProgressBar.classList.remove('bg-success');
        scanProgressBar.classList.remove('bg-danger');
        
        // Reset status
        scanStatus.innerHTML = `
            <p class="text-center text-info">
                <i class="fas fa-spinner fa-spin"></i> Initializing scan...
            </p>
        `;
        
        // Hide result buttons
        viewResultsBtn.style.display = 'none';
        startNewBtn.style.display = 'none';
    });
    
    // Helper function to show alert
    function showAlert(message, type) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.role = 'alert';
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        // Find the form and insert alert before it
        scanForm.parentNode.insertBefore(alertDiv, scanForm);
        
        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.parentNode.removeChild(alertDiv);
            }
        }, 5000);
    }
});
