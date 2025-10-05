// Wait for DOM to load
document.addEventListener('DOMContentLoaded', function() {
  // Tab switching functionality
  const tabs = document.querySelectorAll('.tab');
  const contents = [
    document.getElementById('url-content'),
    document.getElementById('email-content'),
    document.getElementById('stats-content')
  ];
  
  tabs.forEach((tab, index) => {
    tab.addEventListener('click', () => {
      // Update active tab
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      
      // Show selected content
      contents.forEach(c => c.style.display = 'none');
      contents[index].style.display = 'block';
    });
  });
  
  // Load and display history
  loadHistory();
  
  // Clear history buttons
  document.getElementById('clear-url-btn').addEventListener('click', () => {
    chrome.storage.local.set({urlHistory: []}, () => {
      loadHistory();
    });
  });
  
  document.getElementById('clear-email-btn').addEventListener('click', () => {
    chrome.storage.local.set({emailHistory: []}, () => {
      loadHistory();
    });
  });
  
  function loadHistory() {
    // Load URL history
    chrome.storage.local.get(['urlHistory'], (result) => {
      const urlHistory = result.urlHistory || [];
      const urlTableBody = document.getElementById('url-history');
      const urlEmpty = document.getElementById('url-empty');
      
      if (urlHistory.length > 0) {
        urlTableBody.innerHTML = '';
        urlEmpty.style.display = 'none';
        
        urlHistory.forEach(item => {
          const row = document.createElement('tr');
          
          // URL column
          const urlCell = document.createElement('td');
          urlCell.textContent = item.url;
          urlCell.style.maxWidth = '300px';
          urlCell.style.overflow = 'hidden';
          urlCell.style.textOverflow = 'ellipsis';
          urlCell.style.whiteSpace = 'nowrap';
          row.appendChild(urlCell);
          
          // Status column
          const statusCell = document.createElement('td');
          if (item.isPhishing) {
            statusCell.textContent = 'Dangerous';
            statusCell.className = 'status-danger';
          } else {
            statusCell.textContent = 'Safe';
            statusCell.className = 'status-safe';
          }
          row.appendChild(statusCell);
          
          // Risk Level column
          const riskCell = document.createElement('td');
          riskCell.textContent = item.riskLevel;
          row.appendChild(riskCell);
          
          // Confidence column
          const confidenceCell = document.createElement('td');
          confidenceCell.textContent = `${item.confidence}%`;
          row.appendChild(confidenceCell);
          
          // Date column
          const dateCell = document.createElement('td');
          dateCell.textContent = new Date(item.timestamp).toLocaleString();
          row.appendChild(dateCell);
          
          urlTableBody.appendChild(row);
        });
      } else {
        urlTableBody.innerHTML = '';
        urlEmpty.style.display = 'block';
      }
    });
    
    // Load Email history
    chrome.storage.local.get(['emailHistory'], (result) => {
      const emailHistory = result.emailHistory || [];
      const emailTableBody = document.getElementById('email-history');
      const emailEmpty = document.getElementById('email-empty');
      
      if (emailHistory.length > 0) {
        emailTableBody.innerHTML = '';
        emailEmpty.style.display = 'none';
        
        emailHistory.forEach(item => {
          const row = document.createElement('tr');
          
          // Email column
          const emailCell = document.createElement('td');
          emailCell.textContent = item.email;
          row.appendChild(emailCell);
          
          // Status column
          const statusCell = document.createElement('td');
          if (item.isPhishing) {
            statusCell.textContent = 'Suspicious';
            statusCell.className = 'status-danger';
          } else {
            statusCell.textContent = 'Safe';
            statusCell.className = 'status-safe';
          }
          row.appendChild(statusCell);
          
          // Risk Level column
          const riskCell = document.createElement('td');
          riskCell.textContent = item.riskLevel;
          row.appendChild(riskCell);
          
          // Confidence column
          const confidenceCell = document.createElement('td');
          confidenceCell.textContent = `${item.confidence}%`;
          row.appendChild(confidenceCell);
          
          // Reasons column
          const reasonsCell = document.createElement('td');
          if (item.reasons && item.reasons.length > 0) {
            reasonsCell.textContent = item.reasons.join(', ');
          } else {
            reasonsCell.textContent = 'N/A';
          }
          row.appendChild(reasonsCell);
          
          // Date column
          const dateCell = document.createElement('td');
          dateCell.textContent = new Date(item.timestamp).toLocaleString();
          row.appendChild(dateCell);
          
          emailTableBody.appendChild(row);
        });
      } else {
        emailTableBody.innerHTML = '';
        emailEmpty.style.display = 'block';
      }
    });
    
    // Update statistics
    updateStats();
  }
  
  function updateStats() {
    chrome.storage.local.get(['urlHistory', 'emailHistory'], (result) => {
      const urlHistory = result.urlHistory || [];
      const emailHistory = result.emailHistory || [];
      
      // Count URLs
      document.getElementById('urls-count').textContent = urlHistory.length;
      
      // Count Emails
      document.getElementById('emails-count').textContent = emailHistory.length;
      
      // Count Threats
      const urlThreats = urlHistory.filter(item => item.isPhishing).length;
      const emailThreats = emailHistory.filter(item => item.isPhishing).length;
      document.getElementById('threats-count').textContent = urlThreats + emailThreats;
    });
  }
});