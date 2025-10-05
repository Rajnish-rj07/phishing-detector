// Wait for DOM to load
document.addEventListener('DOMContentLoaded', function() {
  console.log('History page loaded');
  
  // Tab switching functionality
  const tabs = document.querySelectorAll('.tab');
  const contentSections = document.querySelectorAll('.content-section');
  
  tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      const targetTab = tab.getAttribute('data-tab');
      
      // Update active tab
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      
      // Show selected content
      contentSections.forEach(section => {
        section.classList.remove('active');
      });
      
      const targetContent = document.getElementById(`${targetTab}-content`);
      if (targetContent) {
        targetContent.classList.add('active');
      }
    });
  });
  
  // Load and display history
  loadHistory();
  
  // Clear history buttons
  document.getElementById('clear-url-btn').addEventListener('click', () => {
    if (confirm('Are you sure you want to clear all URL history?')) {
      chrome.storage.local.set({urlHistory: []}, () => {
        console.log('URL history cleared');
        loadHistory();
      });
    }
  });
  
  document.getElementById('clear-email-btn').addEventListener('click', () => {
    if (confirm('Are you sure you want to clear all email history?')) {
      chrome.storage.local.set({emailHistory: []}, () => {
        console.log('Email history cleared');
        loadHistory();
      });
    }
  });
  
  function loadHistory() {
    console.log('Loading history...');
    
    // Load URL history
    chrome.storage.local.get(['urlHistory'], (result) => {
      const urlHistory = result.urlHistory || [];
      console.log('URL History:', urlHistory);
      
      const urlTableBody = document.getElementById('url-history');
      const urlEmpty = document.getElementById('url-empty');
      const urlTable = document.getElementById('url-table');
      
      if (urlHistory.length > 0) {
        urlTableBody.innerHTML = '';
        urlEmpty.style.display = 'none';
        urlTable.style.display = 'table';
        
        urlHistory.forEach(item => {
          const row = document.createElement('tr');
          
          const urlCell = document.createElement('td');
          urlCell.className = 'url-cell';
          urlCell.textContent = item.url || 'Unknown URL';
          urlCell.title = item.url || 'Unknown URL';
          
          const riskCell = document.createElement('td');
          const riskBadge = document.createElement('span');
          riskBadge.className = `risk-badge risk-${(item.riskLevel || 'unknown').toLowerCase()}`;
          riskBadge.textContent = item.riskLevel || 'UNKNOWN';
          riskCell.appendChild(riskBadge);
          
          const confidenceCell = document.createElement('td');
          confidenceCell.textContent = `${item.confidence || 0}%`;
          
          const timeCell = document.createElement('td');
          timeCell.className = 'timestamp';
          timeCell.textContent = item.timestamp ? new Date(item.timestamp).toLocaleString() : 'Unknown';
          
          row.appendChild(urlCell);
          row.appendChild(riskCell);
          row.appendChild(confidenceCell);
          row.appendChild(timeCell);
          
          urlTableBody.appendChild(row);
        });
      } else {
        urlEmpty.style.display = 'block';
        urlTable.style.display = 'none';
      }
    });
    
    // Load Email history
    chrome.storage.local.get(['emailHistory'], (result) => {
      const emailHistory = result.emailHistory || [];
      console.log('Email History:', emailHistory);
      
      const emailTableBody = document.getElementById('email-history');
      const emailEmpty = document.getElementById('email-empty');
      const emailTable = document.getElementById('email-table');
      
      if (emailHistory.length > 0) {
        emailTableBody.innerHTML = '';
        emailEmpty.style.display = 'none';
        emailTable.style.display = 'table';
        
        emailHistory.forEach(item => {
          const row = document.createElement('tr');
          
          const emailCell = document.createElement('td');
          emailCell.textContent = item.email || 'Unknown Email';
          
          const riskCell = document.createElement('td');
          const riskBadge = document.createElement('span');
          riskBadge.className = `risk-badge risk-${(item.riskLevel || 'unknown').toLowerCase()}`;
          riskBadge.textContent = item.riskLevel || 'UNKNOWN';
          riskCell.appendChild(riskBadge);
          
          const confidenceCell = document.createElement('td');
          confidenceCell.textContent = `${item.confidence || 0}%`;
          
          const timeCell = document.createElement('td');
          timeCell.className = 'timestamp';
          timeCell.textContent = item.timestamp ? new Date(item.timestamp).toLocaleString() : 'Unknown';
          
          row.appendChild(emailCell);
          row.appendChild(riskCell);
          row.appendChild(confidenceCell);
          row.appendChild(timeCell);
          
          emailTableBody.appendChild(row);
        });
      } else {
        emailEmpty.style.display = 'block';
        emailTable.style.display = 'none';
      }
    });
    
    // Update statistics
    updateStatistics();
  }
  
  function updateStatistics() {
    chrome.storage.local.get(['urlHistory', 'emailHistory'], (result) => {
      const urlHistory = result.urlHistory || [];
      const emailHistory = result.emailHistory || [];
      
      const totalChecks = urlHistory.length + emailHistory.length;
      const urlThreats = urlHistory.filter(item => item.isPhishing).length;
      const emailThreats = emailHistory.filter(item => item.isPhishing).length;
      const totalThreats = urlThreats + emailThreats;
      const safeSites = totalChecks - totalThreats;
      const protectionRate = totalChecks > 0 ? Math.round((totalThreats / totalChecks) * 100) : 0;
      
      // Update statistics display
      document.getElementById('total-checks').textContent = totalChecks;
      document.getElementById('threats-detected').textContent = totalThreats;
      document.getElementById('safe-sites').textContent = safeSites;
      document.getElementById('protection-rate').textContent = `${protectionRate}%`;
    });
  }
});