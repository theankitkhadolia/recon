document.addEventListener('DOMContentLoaded', function() {
    const scanId = document.getElementById('scanData').dataset.scanId;
    const targetDomain = document.getElementById('scanData').dataset.target;
    
    // Pagination settings
    const itemsPerPage = 10;
    let currentPage = {
        subdomains: 1,
        ports: 1,
        urls: 1
    };
    
    // Data containers
    let allResults = [];
    let filteredResults = {
        subdomains: [],
        ports: [],
        urls: [],
        other: [],
        errors: []
    };
    
    // Load results data
    loadResults();
    
    // Set up search filters
    document.getElementById('subdomainSearch').addEventListener('input', function() {
        filterAndDisplaySubdomains(this.value);
    });
    
    document.getElementById('portsSearch').addEventListener('input', function() {
        filterAndDisplayPorts(this.value);
    });
    
    document.getElementById('urlsSearch').addEventListener('input', function() {
        filterAndDisplayUrls(this.value);
    });
    
    /**
     * Load scan results from the server
     */
    function loadResults() {
        fetch(`/get_results/${scanId}`)
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    allResults = data.data;
                    processResults(allResults);
                } else {
                    showError('Failed to load scan results. Please try refreshing the page.');
                }
            })
            .catch(error => {
                console.error('Error fetching results:', error);
                showError('Network error occurred while loading results.');
            });
    }
    
    /**
     * Process all results into specific categories
     */
    function processResults(results) {
        const subdomains = new Map();
        const ports = [];
        const urls = new Map();
        const other = [];
        const errors = [];
        
        results.forEach(result => {
            switch(result.result_type) {
                case 'subdomains':
                    if (Array.isArray(result.data)) {
                        result.data.forEach(subdomain => {
                            if (!subdomains.has(subdomain)) {
                                subdomains.set(subdomain, [result.tool]);
                            } else {
                                const tools = subdomains.get(subdomain);
                                if (!tools.includes(result.tool)) {
                                    tools.push(result.tool);
                                }
                            }
                        });
                    }
                    break;
                    
                case 'port_scan':
                    if (Array.isArray(result.data)) {
                        result.data.forEach(hostData => {
                            if (hostData.ports && Array.isArray(hostData.ports)) {
                                hostData.ports.forEach(port => {
                                    ports.push({
                                        ip: hostData.ip,
                                        port: port.port,
                                        protocol: port.protocol,
                                        service: port.service,
                                        version: port.version,
                                        state: port.state
                                    });
                                });
                            }
                        });
                    }
                    break;
                    
                case 'urls':
                    if (Array.isArray(result.data)) {
                        result.data.forEach(url => {
                            if (!urls.has(url)) {
                                urls.set(url, [result.tool]);
                            } else {
                                const tools = urls.get(url);
                                if (!tools.includes(result.tool)) {
                                    tools.push(result.tool);
                                }
                            }
                        });
                    }
                    break;
                    
                case 'findings':
                    if (Array.isArray(result.data)) {
                        result.data.forEach(finding => {
                            other.push({
                                type: finding.type || 'unknown',
                                value: finding.value,
                                tool: result.tool
                            });
                        });
                    }
                    break;
                    
                case 'error':
                    errors.push({
                        tool: result.tool,
                        message: result.data.message || 'Unknown error'
                    });
                    break;
                    
                default:
                    // Store any other result types
                    other.push({
                        type: result.result_type,
                        data: result.data,
                        tool: result.tool
                    });
            }
        });
        
        // Convert maps to arrays
        filteredResults.subdomains = Array.from(subdomains).map(([subdomain, tools]) => ({
            subdomain,
            tools
        }));
        
        filteredResults.ports = ports;
        
        filteredResults.urls = Array.from(urls).map(([url, tools]) => ({
            url,
            tools
        }));
        
        filteredResults.other = other;
        filteredResults.errors = errors;
        
        // Display results
        displaySubdomains();
        displayPorts();
        displayUrls();
        displayOtherFindings();
        displayErrors();
    }
    
    /**
     * Filter and display subdomains
     */
    function filterAndDisplaySubdomains(searchTerm) {
        if (!searchTerm) {
            filteredResults.subdomains = Array.from(new Map(allResults
                .filter(result => result.result_type === 'subdomains')
                .flatMap(result => 
                    Array.isArray(result.data) ? 
                    result.data.map(subdomain => [subdomain, [result.tool]]) : 
                    []
                )
            ).entries())
            .map(([subdomain, tools]) => ({
                subdomain,
                tools: Array.from(new Set(tools.flat()))
            }));
        } else {
            const searchTermLower = searchTerm.toLowerCase();
            
            // Create a filtered map of subdomains
            const filteredMap = new Map();
            
            allResults
                .filter(result => result.result_type === 'subdomains')
                .forEach(result => {
                    if (Array.isArray(result.data)) {
                        result.data
                            .filter(subdomain => 
                                subdomain.toLowerCase().includes(searchTermLower)
                            )
                            .forEach(subdomain => {
                                if (!filteredMap.has(subdomain)) {
                                    filteredMap.set(subdomain, [result.tool]);
                                } else {
                                    const tools = filteredMap.get(subdomain);
                                    if (!tools.includes(result.tool)) {
                                        tools.push(result.tool);
                                    }
                                }
                            });
                    }
                });
                
            filteredResults.subdomains = Array.from(filteredMap).map(([subdomain, tools]) => ({
                subdomain,
                tools
            }));
        }
        
        // Reset to first page and display
        currentPage.subdomains = 1;
        displaySubdomains();
    }
    
    /**
     * Display subdomains with pagination
     */
    function displaySubdomains() {
        const tableBody = document.getElementById('subdomainsTable');
        const paginationContainer = document.querySelector('#subdomainsPagination .pagination');
        const countElement = document.getElementById('subdomainsCount');
        
        // Update count
        countElement.textContent = `${filteredResults.subdomains.length} subdomains found`;
        
        // Clear table
        tableBody.innerHTML = '';
        
        if (filteredResults.subdomains.length === 0) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="3" class="text-center">
                        <p class="my-3 text-muted">No subdomains found</p>
                    </td>
                </tr>
            `;
            paginationContainer.innerHTML = '';
            return;
        }
        
        // Calculate pagination
        const totalPages = Math.ceil(filteredResults.subdomains.length / itemsPerPage);
        const startIndex = (currentPage.subdomains - 1) * itemsPerPage;
        const endIndex = Math.min(startIndex + itemsPerPage, filteredResults.subdomains.length);
        
        // Get current page data
        const currentPageData = filteredResults.subdomains.slice(startIndex, endIndex);
        
        // Render table rows
        currentPageData.forEach(item => {
            const row = document.createElement('tr');
            
            const toolBadges = item.tools.map(tool => 
                `<span class="badge bg-info me-1">${tool}</span>`
            ).join('');
            
            row.innerHTML = `
                <td>${item.subdomain}</td>
                <td>${toolBadges}</td>
                <td>
                    <a href="https://${item.subdomain}" class="btn btn-sm btn-outline-primary" target="_blank" title="Open in new tab">
                        <i class="fas fa-external-link-alt"></i>
                    </a>
                </td>
            `;
            
            tableBody.appendChild(row);
        });
        
        // Update pagination
        updatePagination(paginationContainer, totalPages, currentPage.subdomains, 'subdomains');
    }
    
    /**
     * Filter and display ports
     */
    function filterAndDisplayPorts(searchTerm) {
        if (!searchTerm) {
            filteredResults.ports = allResults
                .filter(result => result.result_type === 'port_scan')
                .flatMap(result => 
                    Array.isArray(result.data) ? 
                    result.data.flatMap(hostData => 
                        Array.isArray(hostData.ports) ?
                        hostData.ports.map(port => ({
                            ip: hostData.ip,
                            port: port.port,
                            protocol: port.protocol,
                            service: port.service,
                            version: port.version,
                            state: port.state
                        })) : []
                    ) : []
                );
        } else {
            const searchTermLower = searchTerm.toLowerCase();
            
            filteredResults.ports = allResults
                .filter(result => result.result_type === 'port_scan')
                .flatMap(result => 
                    Array.isArray(result.data) ? 
                    result.data.flatMap(hostData => 
                        Array.isArray(hostData.ports) ?
                        hostData.ports
                            .filter(port => 
                                port.port.toString().includes(searchTerm) ||
                                port.service.toLowerCase().includes(searchTermLower) ||
                                port.protocol.toLowerCase().includes(searchTermLower) ||
                                port.version.toLowerCase().includes(searchTermLower) ||
                                hostData.ip.includes(searchTerm)
                            )
                            .map(port => ({
                                ip: hostData.ip,
                                port: port.port,
                                protocol: port.protocol,
                                service: port.service,
                                version: port.version,
                                state: port.state
                            })) : []
                    ) : []
                );
        }
        
        // Reset to first page and display
        currentPage.ports = 1;
        displayPorts();
    }
    
    /**
     * Display ports with pagination
     */
    function displayPorts() {
        const tableBody = document.getElementById('portsTable');
        const paginationContainer = document.querySelector('#portsPagination .pagination');
        const countElement = document.getElementById('portsCount');
        
        // Update count
        countElement.textContent = `${filteredResults.ports.length} ports found`;
        
        // Clear table
        tableBody.innerHTML = '';
        
        if (filteredResults.ports.length === 0) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center">
                        <p class="my-3 text-muted">No open ports found</p>
                    </td>
                </tr>
            `;
            paginationContainer.innerHTML = '';
            return;
        }
        
        // Calculate pagination
        const totalPages = Math.ceil(filteredResults.ports.length / itemsPerPage);
        const startIndex = (currentPage.ports - 1) * itemsPerPage;
        const endIndex = Math.min(startIndex + itemsPerPage, filteredResults.ports.length);
        
        // Get current page data
        const currentPageData = filteredResults.ports.slice(startIndex, endIndex);
        
        // Render table rows
        currentPageData.forEach(port => {
            const row = document.createElement('tr');
            
            // Determine state badge color
            let stateBadgeClass = 'bg-secondary';
            if (port.state === 'open') {
                stateBadgeClass = 'bg-success';
            } else if (port.state === 'closed') {
                stateBadgeClass = 'bg-danger';
            } else if (port.state === 'filtered') {
                stateBadgeClass = 'bg-warning';
            }
            
            row.innerHTML = `
                <td>${port.ip}</td>
                <td>${port.port}</td>
                <td>${port.protocol}</td>
                <td>${port.service || 'unknown'}</td>
                <td>${port.version || 'unknown'}</td>
                <td><span class="badge ${stateBadgeClass}">${port.state}</span></td>
            `;
            
            tableBody.appendChild(row);
        });
        
        // Update pagination
        updatePagination(paginationContainer, totalPages, currentPage.ports, 'ports');
    }
    
    /**
     * Filter and display URLs
     */
    function filterAndDisplayUrls(searchTerm) {
        if (!searchTerm) {
            const urlMap = new Map();
            
            allResults
                .filter(result => result.result_type === 'urls')
                .forEach(result => {
                    if (Array.isArray(result.data)) {
                        result.data.forEach(url => {
                            if (!urlMap.has(url)) {
                                urlMap.set(url, [result.tool]);
                            } else {
                                const tools = urlMap.get(url);
                                if (!tools.includes(result.tool)) {
                                    tools.push(result.tool);
                                }
                            }
                        });
                    }
                });
                
            filteredResults.urls = Array.from(urlMap).map(([url, tools]) => ({
                url,
                tools
            }));
        } else {
            const searchTermLower = searchTerm.toLowerCase();
            const urlMap = new Map();
            
            allResults
                .filter(result => result.result_type === 'urls')
                .forEach(result => {
                    if (Array.isArray(result.data)) {
                        result.data
                            .filter(url => url.toLowerCase().includes(searchTermLower))
                            .forEach(url => {
                                if (!urlMap.has(url)) {
                                    urlMap.set(url, [result.tool]);
                                } else {
                                    const tools = urlMap.get(url);
                                    if (!tools.includes(result.tool)) {
                                        tools.push(result.tool);
                                    }
                                }
                            });
                    }
                });
                
            filteredResults.urls = Array.from(urlMap).map(([url, tools]) => ({
                url,
                tools
            }));
        }
        
        // Reset to first page and display
        currentPage.urls = 1;
        displayUrls();
    }
    
    /**
     * Display URLs with pagination
     */
    function displayUrls() {
        const tableBody = document.getElementById('urlsTable');
        const paginationContainer = document.querySelector('#urlsPagination .pagination');
        const countElement = document.getElementById('urlsCount');
        
        // Update count
        countElement.textContent = `${filteredResults.urls.length} URLs found`;
        
        // Clear table
        tableBody.innerHTML = '';
        
        if (filteredResults.urls.length === 0) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="3" class="text-center">
                        <p class="my-3 text-muted">No URLs found</p>
                    </td>
                </tr>
            `;
            paginationContainer.innerHTML = '';
            return;
        }
        
        // Calculate pagination
        const totalPages = Math.ceil(filteredResults.urls.length / itemsPerPage);
        const startIndex = (currentPage.urls - 1) * itemsPerPage;
        const endIndex = Math.min(startIndex + itemsPerPage, filteredResults.urls.length);
        
        // Get current page data
        const currentPageData = filteredResults.urls.slice(startIndex, endIndex);
        
        // Render table rows
        currentPageData.forEach(item => {
            const row = document.createElement('tr');
            
            const toolBadges = item.tools.map(tool => 
                `<span class="badge bg-info me-1">${tool}</span>`
            ).join('');
            
            // Truncate long URLs
            let displayUrl = item.url;
            const maxLength = 100;
            if (displayUrl.length > maxLength) {
                displayUrl = displayUrl.substring(0, maxLength) + '...';
            }
            
            row.innerHTML = `
                <td title="${item.url}">${displayUrl}</td>
                <td>${toolBadges}</td>
                <td>
                    <a href="${item.url}" class="btn btn-sm btn-outline-primary" target="_blank" title="Open in new tab">
                        <i class="fas fa-external-link-alt"></i>
                    </a>
                </td>
            `;
            
            tableBody.appendChild(row);
        });
        
        // Update pagination
        updatePagination(paginationContainer, totalPages, currentPage.urls, 'urls');
    }
    
    /**
     * Display other findings
     */
    function displayOtherFindings() {
        const container = document.getElementById('otherFindings');
        
        // Clear container
        container.innerHTML = '';
        
        if (filteredResults.other.length === 0) {
            container.innerHTML = `
                <div class="text-center my-4">
                    <p class="text-muted">No additional findings found</p>
                </div>
            `;
            return;
        }
        
        // Group findings by type
        const findingsByType = {};
        filteredResults.other.forEach(finding => {
            if (!findingsByType[finding.type]) {
                findingsByType[finding.type] = [];
            }
            findingsByType[finding.type].push(finding);
        });
        
        // Display each type in an accordion
        const accordion = document.createElement('div');
        accordion.className = 'accordion';
        accordion.id = 'otherFindingsAccordion';
        
        let index = 0;
        for (const [type, findings] of Object.entries(findingsByType)) {
            const accordionItem = document.createElement('div');
            accordionItem.className = 'accordion-item';
            
            const headerId = `heading-${type}-${index}`;
            const collapseId = `collapse-${type}-${index}`;
            
            accordionItem.innerHTML = `
                <h2 class="accordion-header" id="${headerId}">
                    <button class="accordion-button ${index > 0 ? 'collapsed' : ''}" type="button" data-bs-toggle="collapse" data-bs-target="#${collapseId}" aria-expanded="${index === 0 ? 'true' : 'false'}" aria-controls="${collapseId}">
                        ${capitalizeFirstLetter(type)} (${findings.length})
                    </button>
                </h2>
                <div id="${collapseId}" class="accordion-collapse collapse ${index === 0 ? 'show' : ''}" aria-labelledby="${headerId}" data-bs-parent="#otherFindingsAccordion">
                    <div class="accordion-body">
                        <div class="list-group">
                            ${findings.map(finding => `
                                <div class="list-group-item list-group-item-action">
                                    <div class="d-flex w-100 justify-content-between">
                                        <h6 class="mb-1">${finding.value || JSON.stringify(finding.data)}</h6>
                                        <small class="text-muted">
                                            <span class="badge bg-info">${finding.tool}</span>
                                        </small>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                </div>
            `;
            
            accordion.appendChild(accordionItem);
            index++;
        }
        
        container.appendChild(accordion);
    }
    
    /**
     * Display errors
     */
    function displayErrors() {
        const container = document.getElementById('errorsList');
        
        // Clear container
        container.innerHTML = '';
        
        if (filteredResults.errors.length === 0) {
            container.innerHTML = `
                <div class="text-center my-4">
                    <p class="text-muted">No errors reported</p>
                </div>
            `;
            return;
        }
        
        // Render errors as list
        const list = document.createElement('div');
        list.className = 'list-group';
        
        filteredResults.errors.forEach(error => {
            const item = document.createElement('div');
            item.className = 'list-group-item list-group-item-danger';
            
            item.innerHTML = `
                <div class="d-flex w-100 justify-content-between">
                    <h6 class="mb-1">${error.tool}</h6>
                    <small>Error</small>
                </div>
                <p class="mb-1">${error.message}</p>
            `;
            
            list.appendChild(item);
        });
        
        container.appendChild(list);
    }
    
    /**
     * Update pagination controls
     */
    function updatePagination(container, totalPages, currentPageNum, category) {
        container.innerHTML = '';
        
        if (totalPages <= 1) {
            return;
        }
        
        // Previous button
        const prevLi = document.createElement('li');
        prevLi.className = `page-item ${currentPageNum === 1 ? 'disabled' : ''}`;
        
        const prevLink = document.createElement('a');
        prevLink.className = 'page-link';
        prevLink.href = '#';
        prevLink.innerHTML = '&laquo;';
        prevLink.setAttribute('aria-label', 'Previous');
        
        if (currentPageNum > 1) {
            prevLink.addEventListener('click', function(e) {
                e.preventDefault();
                currentPage[category]--;
                updateDisplay(category);
            });
        }
        
        prevLi.appendChild(prevLink);
        container.appendChild(prevLi);
        
        // Page numbers
        const maxVisiblePages = 5;
        let startPage = Math.max(1, currentPageNum - Math.floor(maxVisiblePages / 2));
        let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);
        
        if (endPage - startPage + 1 < maxVisiblePages) {
            startPage = Math.max(1, endPage - maxVisiblePages + 1);
        }
        
        for (let i = startPage; i <= endPage; i++) {
            const pageLi = document.createElement('li');
            pageLi.className = `page-item ${i === currentPageNum ? 'active' : ''}`;
            
            const pageLink = document.createElement('a');
            pageLink.className = 'page-link';
            pageLink.href = '#';
            pageLink.textContent = i;
            
            if (i !== currentPageNum) {
                pageLink.addEventListener('click', function(e) {
                    e.preventDefault();
                    currentPage[category] = i;
                    updateDisplay(category);
                });
            }
            
            pageLi.appendChild(pageLink);
            container.appendChild(pageLi);
        }
        
        // Next button
        const nextLi = document.createElement('li');
        nextLi.className = `page-item ${currentPageNum === totalPages ? 'disabled' : ''}`;
        
        const nextLink = document.createElement('a');
        nextLink.className = 'page-link';
        nextLink.href = '#';
        nextLink.innerHTML = '&raquo;';
        nextLink.setAttribute('aria-label', 'Next');
        
        if (currentPageNum < totalPages) {
            nextLink.addEventListener('click', function(e) {
                e.preventDefault();
                currentPage[category]++;
                updateDisplay(category);
            });
        }
        
        nextLi.appendChild(nextLink);
        container.appendChild(nextLi);
    }
    
    /**
     * Update display based on category
     */
    function updateDisplay(category) {
        switch(category) {
            case 'subdomains':
                displaySubdomains();
                break;
            case 'ports':
                displayPorts();
                break;
            case 'urls':
                displayUrls();
                break;
        }
    }
    
    /**
     * Helper function to capitalize first letter
     */
    function capitalizeFirstLetter(string) {
        return string.charAt(0).toUpperCase() + string.slice(1);
    }
    
    /**
     * Show error message
     */
    function showError(message) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'alert alert-danger alert-dismissible fade show mt-3';
        errorDiv.role = 'alert';
        errorDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        document.querySelector('main').prepend(errorDiv);
    }
});
