async function scanCurrentTab() {
    const statusElem = document.getElementById('status');
    const container = document.getElementById('result-container');
    const resultText = document.getElementById('result-text');
    const probBar = document.getElementById('prob-bar');
    const probText = document.getElementById('probability-text');
    const risksDiv = document.getElementById('risks');
    
    try {
        statusElem.textContent = '🔍 Scanning URL...';
        
        let [tab] = await chrome.tabs.query({active: true, currentWindow: true});
        
        if (!tab || !tab.url) {
            statusElem.textContent = 'No URL found.';
            return;
        }
        
        // Send URL to backend
        const response = await fetch('http://localhost:8000/score', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url: tab.url})
        });
        
        if (!response.ok) {
            throw new Error('Server connection failed');
        }
        
        const data = await response.json();
        
        // Update UI
        statusElem.style.display = 'none';
        container.style.display = 'block';
        
        if (data.label === "Phishing") {
            resultText.textContent = "⚠️ PHISHING DETECTED";
            resultText.className = "phishing";
            probBar.style.backgroundColor = "#c0392b";
        } else {
            resultText.textContent = "✅ SAFE WEBSITE";
            resultText.className = "safe";
            probBar.style.backgroundColor = "#27ae60";
        }
        
        // Probability Bar
        const percent = Math.round(data.probability * 100);
        probBar.style.width = percent + "%";
        probText.textContent = `Confidence: ${percent}%`;
        
        // Render Risk Factors
        risksDiv.innerHTML = '';
        if (data.risk_factors && data.risk_factors.length > 0) {
            data.risk_factors.forEach(risk => {
                const div = document.createElement('div');
                div.className = 'risk-item';
                div.textContent = `• ${risk}`;
                risksDiv.appendChild(div);
            });
        } else if (data.label === "Safe") {
            const div = document.createElement('div');
            div.className = 'safe-item';
            div.textContent = "✓ No obvious risks detected";
            risksDiv.appendChild(div);
        }
        
    } catch (e) {
        statusElem.textContent = '❌ Error: ' + e.message;
        statusElem.style.color = 'red';
    }
}

document.addEventListener('DOMContentLoaded', scanCurrentTab);
